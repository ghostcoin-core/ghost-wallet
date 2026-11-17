// A Ghost Java Card (the applet in card-applet/, docs/bearer-card-spec.md),
// over Core NFC. Each flow runs here, natively, in one reader session: the
// card's commands and answers never reach JavaScript. JavaScript gets the
// public parts the native core verifies (Identify, the certificate, the seal
// statement and its signature, the commit data, and Make's fill and
// commitment) and nothing else: an Open's answer goes from the card straight
// to the native core (ghost_wallet_java_card_take_open), which holds the
// released seed material until the coin it makes is checked, for the Summon
// or Claim. The card is a bearer object: no flow takes a code or PIN.
//
// Every flow starts with SELECT and Identify and decides from the card's
// state what is left to do, so a card pulled away mid-flow is asked for
// again on the same sheet and the flow carries on: a Make whose answer was
// lost reads the commit data back, an Open that went through answers again
// with the same seed material, and a Refill that went through is not sent
// twice. While a flow runs, the sheet shows how far it has got and the holder
// feels it ticking (TapFeedback.swift).
import ExpoModulesCore
import Foundation

final class GhostCardNotReadyException: Exception {
  override var reason: String { "This Ghost card was not finished at its loading station." }
}

final class GhostCardStateException: GenericException<String> {
  override var reason: String { "The card is \(param), so this cannot be done with it." }
}

final class GhostCardNoChecksException: Exception {
  override var reason: String { "The card has too few seal checks left for this." }
}

final class GhostCardFailedException: GenericException<String> {
  override var reason: String { "The card refused a command (\(param))." }
}

final class GhostCardBusyException: Exception {
  override var reason: String { "Another card tap is under way." }
}

final class GhostCardBadInputException: Exception {
  override var reason: String { "The card flow was asked with input of the wrong size." }
}

/// The card answered a status word other than 9000.
private struct CardStatus: Error {
  let ins: UInt8
  let sw: UInt16
}

/// The card left the field, or the session ended, mid-command.
private struct CardLost: Error {}

final class JavaCard {
  private let reader: TagReader
  /// Every flow runs here, one at a time, and blocks on each command.
  private let queue = DispatchQueue(label: "com.ghostcoin.wallet.java-card")
  private var running = false
  private let lock = NSLock()

  static let aid = Data([0xA0, 0x00, 0x00, 0x08, 0x47, 0x47, 0x43, 0x41, 0x52, 0x44, 0x01])
  static let statementBytes = 193
  static let signatureBytes = 2508
  static let commitDataBytes = 430
  static let identifyBytes = 29
  /// Open's answer: fill 4, card random 32, writer nonce 32.
  static let openAnswerBytes = 68
  /// The longest answer asked for in one command. iPhone NFC takes extended
  /// answers; the card cuts an answer to what it can send, and the parts are
  /// read on from where it stopped.
  static let maxAnswer = 1024
  /// How many times a flow asks for the card again after losing it.
  static let maxReconnects = 3
  /// How long a command or a reconnect may take.
  static let commandTimeout: DispatchTimeInterval = .seconds(10)
  static let reconnectTimeout: DispatchTimeInterval = .seconds(30)

  private static let swNoChecks: UInt16 = 0x6984

  init(reader: TagReader) {
    self.reader = reader
  }

  // MARK: The flows

  /// Check: Identify, the certificate, a Check over `challenge` and its
  /// signature, and, when the card is sealed and `commitData` is asked, the
  /// commit data.
  func check(alert: String, challenge: Data, commitData: Bool, promise: Promise) {
    guard challenge.count == 32 else {
      promise.reject(GhostCardBadInputException())
      return
    }
    run(alert: alert, working: "Checking the card", steps: commitData ? 15 : 14, promise: promise) { link, out in
      let id = try self.identify(link, out)
      try self.readCheck(link, out, identity: id, challenge: challenge)
      if commitData, id.state == 1 {
        out["commitData"] = try self.readParts(link, ins: 0x22, total: Self.commitDataBytes)
      }
    }
  }

  /// Fill: Make on a blank card with `input` (the amount, chain id and writer
  /// nonce, 52 bytes), then, in the same tap, the certificate and a Check over
  /// `challenge`. A Make cut off is not sent again: the card says sealed at
  /// the next fill, and its commit data is read back.
  func fill(alert: String, make input: Data, challenge: Data, promise: Promise) {
    guard input.count == 52, challenge.count == 32 else {
      promise.reject(GhostCardBadInputException())
      return
    }
    // What carries over between attempts of this one tap.
    var startFill: UInt32?
    var made: Data?
    run(alert: alert, working: "Filling the card", steps: 16, promise: promise) { link, out in
      let id = try self.identify(link, out)
      if startFill == nil {
        guard id.state == 0 else { throw GhostCardStateException(Self.stateName(id.state)) }
        startFill = id.fill
      }
      if made == nil {
        if id.state == 0 && id.fill == startFill {
          let first = try self.send(link, ins: 0x20, p1p2: 0, data: input, le: 466)
          guard first.count >= 36 else { throw CardStatus(ins: 0x20, sw: 0x6F00) }
          var answer = first
          // The rest of the commit data, if the card cut the answer.
          var have = first.count - 36
          while have < Self.commitDataBytes {
            let part = try self.send(
              link, ins: 0x22, p1p2: UInt16(have), data: nil, le: min(Self.maxAnswer, Self.commitDataBytes - have))
            guard !part.isEmpty else { throw CardStatus(ins: 0x22, sw: 0x6F00) }
            answer.append(part)
            have += part.count
          }
          made = answer
        } else if id.state == 1, let start = startFill, id.fill == start &+ 1 {
          // The Make went through and its answer was lost: the card is
          // sealed at the next fill. Its commit data is read back; the
          // commitment comes from the signed statement.
          let data = try self.readParts(link, ins: 0x22, total: Self.commitDataBytes)
          made = Self.u32(id.fill) + Data(count: 32) + data
        } else {
          throw GhostCardStateException(Self.stateName(id.state))
        }
      }
      out["make"] = made
      try self.readCheck(link, out, identity: try self.identify(link, out), challenge: challenge)
    }
  }

  /// Open: the certificate, a Check over `checkChallenge`, the commit data
  /// while the card is still sealed, then Open, which needs nothing but the
  /// card. The answer goes to the native core only.
  func open(alert: String, checkChallenge: Data, promise: Promise) {
    guard checkChallenge.count == 32 else {
      promise.reject(GhostCardBadInputException())
      return
    }
    var commitData: Data?
    run(alert: alert, working: "Opening the card", steps: 16, promise: promise) { link, out in
      let id = try self.identify(link, out)
      guard id.state == 1 || id.state == 2 else { throw GhostCardStateException(Self.stateName(id.state)) }
      if id.checksLeft > 0 {
        try self.readCheck(link, out, identity: id, challenge: checkChallenge)
      } else {
        out["certificate"] = try self.readParts(link, ins: 0x12, total: Int(id.certLength))
      }
      if id.state == 1, commitData == nil {
        commitData = try self.readParts(link, ins: 0x22, total: Self.commitDataBytes)
      }
      if let commitData {
        out["commitData"] = commitData
      }
      let answer = try self.send(link, ins: 0x40, p1p2: 0, data: nil, le: Self.openAnswerBytes)
      let taken = Self.takeOpen(cardId: id.cardId, answer: answer)
      out["opened"] = taken
      out["openTaken"] = taken
    }
  }

  /// Refill: an opened card goes back to blank. A Refill that went through
  /// before the card was lost is not sent again.
  func refill(alert: String, promise: Promise) {
    var startFill: UInt32?
    run(alert: alert, working: "Clearing the card", steps: 4, promise: promise) { link, out in
      let id = try self.identify(link, out)
      if startFill == nil {
        guard id.state == 2 else { throw GhostCardStateException(Self.stateName(id.state)) }
        startFill = id.fill
      }
      if id.state == 2 {
        // No answer data; asked as a short Le so the command is never header-only.
        _ = try self.send(link, ins: 0x50, p1p2: 0, data: nil, le: 256)
      } else if !(id.state == 0 && id.fill == startFill) {
        throw GhostCardStateException(Self.stateName(id.state))
      }
      _ = try self.identify(link, out)
    }
  }

  // MARK: The steps

  private struct Identity {
    let phase: UInt8
    let state: UInt8
    let cardId: Data
    let fill: UInt32
    let checksLeft: UInt16
    let certLength: UInt16
  }

  private func identify(_ link: Link, _ out: Out) throws -> Identity {
    let r = [UInt8](try send(link, ins: 0x10, p1p2: 0, data: nil, le: Self.identifyBytes))
    guard r.count == Self.identifyBytes, r[0] == 1 else { throw CardStatus(ins: 0x10, sw: 0x6F00) }
    out["identify"] = Data(r)
    let id = Identity(
      phase: r[1], state: r[2], cardId: Data(r[3..<19]),
      fill: UInt32(r[19]) << 24 | UInt32(r[20]) << 16 | UInt32(r[21]) << 8 | UInt32(r[22]),
      checksLeft: UInt16(r[23]) << 8 | UInt16(r[24]),
      certLength: UInt16(r[27]) << 8 | UInt16(r[28])
    )
    guard id.phase == 1 else { throw GhostCardNotReadyException() }
    return id
  }

  /// The certificate (once per tap), a Check and its whole signature.
  private func readCheck(_ link: Link, _ out: Out, identity: Identity, challenge: Data) throws {
    if out["certificate"] == nil {
      out["certificate"] = try readParts(link, ins: 0x12, total: Int(identity.certLength))
    }
    let start = DispatchTime.now().uptimeNanoseconds
    let statement: Data
    do {
      statement = try send(link, ins: 0x30, p1p2: 0, data: challenge, le: Self.statementBytes)
    } catch let status as CardStatus where status.sw == Self.swNoChecks {
      throw GhostCardNoChecksException()
    }
    guard statement.count == Self.statementBytes else { throw CardStatus(ins: 0x30, sw: 0x6F00) }
    // Read straight after the Check: any other command ends its signature.
    let signature = try readParts(link, ins: 0x32, total: Self.signatureBytes)
    out["statement"] = statement
    out["signature"] = signature
    out["checkMs"] = Double(DispatchTime.now().uptimeNanoseconds - start) / 1e6
  }

  private func readParts(_ link: Link, ins: UInt8, total: Int) throws -> Data {
    var out = Data()
    while out.count < total {
      let part = try send(link, ins: ins, p1p2: UInt16(out.count), data: nil, le: min(Self.maxAnswer, total - out.count))
      guard !part.isEmpty else { throw CardStatus(ins: ins, sw: 0x6F00) }
      out.append(part)
    }
    return out
  }

  private func send(_ link: Link, ins: UInt8, p1p2: UInt16, data: Data?, le: Int) throws -> Data {
    let answer = try link.transmit(Self.apdu(cla: 0x80, ins: ins, p1: UInt8(p1p2 >> 8), p2: UInt8(p1p2 & 0xFF), data: data, le: le))
    let sw = UInt16(answer[answer.endIndex - 2]) << 8 | UInt16(answer[answer.endIndex - 1])
    guard sw == 0x9000 else { throw CardStatus(ins: ins, sw: sw) }
    return answer.prefix(answer.count - 2)
  }

  /// A command APDU, short or extended as its lengths need.
  static func apdu(cla: UInt8, ins: UInt8, p1: UInt8, p2: UInt8, data: Data?, le: Int) -> Data {
    let lc = data?.count ?? 0
    let extended = lc > 255 || le > 256
    var out = Data([cla, ins, p1, p2])
    if lc > 0, let data {
      if extended {
        out.append(contentsOf: [0, UInt8(lc >> 8), UInt8(lc & 0xFF)])
      } else {
        out.append(UInt8(lc))
      }
      out.append(data)
    }
    if le > 0 {
      if extended {
        if lc == 0 { out.append(0) }
        out.append(contentsOf: [UInt8((le >> 8) & 0xFF), UInt8(le & 0xFF)])
      } else {
        out.append(le == 256 ? 0 : UInt8(le))
      }
    }
    return out
  }

  // MARK: Running a flow

  /// The answers of a flow, by name; resolved to JavaScript as they are.
  private final class Out {
    var values: [String: Any] = [:]
    subscript(key: String) -> Any? {
      get { values[key] }
      set { values[key] = newValue }
    }
  }

  /// Sends one APDU on the connected card, blocking the flow's queue, and
  /// shows on the sheet how far the flow has got.
  private final class Link {
    let reader: TagReader
    let working: String
    /// About how many commands the flow sends, for its progress.
    let steps: Int
    var commands = 0

    init(reader: TagReader, working: String, steps: Int) {
      self.reader = reader
      self.working = working
      self.steps = max(steps, 1)
    }

    /// "Checking the card ▰▰▰▱▱▱▱▱▱▱ 30%", held below 100% until the flow ends.
    func showProgress() {
      let percent = min(95, commands * 100 / steps)
      let filled = percent / 10
      let bar = String(repeating: "▰", count: filled) + String(repeating: "▱", count: 10 - filled)
      reader.update(alert: "\(working)  \(bar)  \(percent)%\nKeep holding it still.")
    }

    func transmit(_ apdu: Data) throws -> Data {
      let done = DispatchSemaphore(value: 0)
      var answer: Data?
      reader.send(apdu) { result in
        answer = result
        done.signal()
      }
      guard done.wait(timeout: .now() + JavaCard.commandTimeout) == .success, let answer, answer.count >= 2 else {
        throw CardLost()
      }
      commands += 1
      showProgress()
      return answer
    }

    func select() throws {
      let answer = try transmit(JavaCard.apdu(cla: 0x00, ins: 0xA4, p1: 0x04, p2: 0x00, data: JavaCard.aid, le: 0))
      guard answer.suffix(2) == Data([0x90, 0x00]) else {
        throw CardStatus(ins: 0xA4, sw: UInt16(answer[answer.endIndex - 2]) << 8 | UInt16(answer[answer.endIndex - 1]))
      }
    }
  }

  /// Opens the card sheet, runs `body` on the card tapped, and resolves with
  /// what it put in `out`. A card lost mid-flow is asked for again (up to
  /// `maxReconnects` times) and `body` runs again from the start; a flow is
  /// written so that is safe. An NTAG 424 card resolves `{ kind: "ntag" }`
  /// with nothing sent to it.
  private func run(
    alert: String, working: String, steps: Int, promise: Promise, body: @escaping (Link, Out) throws -> Void
  ) {
    lock.lock()
    guard !running else {
      lock.unlock()
      promise.reject(GhostCardBusyException())
      return
    }
    running = true
    lock.unlock()
    queue.async {
      let started = DispatchTime.now().uptimeNanoseconds
      let link = Link(reader: self.reader, working: working, steps: steps)
      let out = Out()
      var reconnects = 0
      var connect: Result<TappedCard, Exception> = self.waitForCard { self.reader.begin(alert: alert, onConnected: $0) }
      while true {
        let tapped: TappedCard
        switch connect {
        case let .failure(error):
          self.finish(promise, error: error)
          return
        case let .success(kind):
          tapped = kind
        }
        if tapped == .ntag {
          self.reader.end(alert: "This is an NTAG 424 card.", error: nil)
          self.done()
          promise.resolve(["kind": "ntag"])
          return
        }
        do {
          try link.select()
          try body(link, out)
          out["kind"] = "ghost"
          out["ms"] = Double(DispatchTime.now().uptimeNanoseconds - started) / 1e6
          out["commands"] = link.commands
          out["reconnects"] = reconnects
          self.reader.end(alert: "Done.", error: nil)
          self.done()
          promise.resolve(out.values.mapValues { value -> Any in (value as? Data).map(Self.hex) ?? value })
          return
        } catch is CardLost {
          reconnects += 1
          guard reconnects <= Self.maxReconnects else {
            self.finish(promise, error: NfcSessionException())
            return
          }
          connect = self.waitForCard {
            self.reader.reconnect(alert: "The card moved. Hold it still near the top of the iPhone.", onConnected: $0)
          }
        } catch let status as CardStatus {
          if status.ins == 0xA4 {
            // Not the Ghost applet: some other ISO 7816 card.
            self.finish(promise, error: GhostCardFailedException("not a Ghost card"))
          } else {
            self.finish(promise, error: GhostCardFailedException(String(format: "%02X %04X", status.ins, status.sw)))
          }
          return
        } catch let error as Exception {
          self.finish(promise, error: error)
          return
        } catch {
          self.finish(promise, error: NfcSessionException())
          return
        }
      }
    }
  }

  /// Blocks until `start` calls back with a connected card's kind.
  private func waitForCard(_ start: (@escaping (Result<Data, Exception>) -> Void) -> Void) -> Result<TappedCard, Exception> {
    let done = DispatchSemaphore(value: 0)
    var result: Result<TappedCard, Exception> = .failure(NfcSessionException())
    start { connected in
      // Called on the reader's queue, where the kind was set.
      switch connected {
      case .success: result = .success(self.reader.tapped)
      case let .failure(error): result = .failure(error)
      }
      done.signal()
    }
    if done.wait(timeout: .now() + Self.reconnectTimeout) != .success {
      return .failure(NfcSessionException())
    }
    return result
  }

  private func finish(_ promise: Promise, error: Exception) {
    let quiet = error is NfcCancelledException || error is NfcUnavailableException
    reader.end(alert: nil, error: quiet ? nil : error.reason)
    done()
    promise.reject(error)
  }

  private func done() {
    lock.lock()
    running = false
    lock.unlock()
  }

  // MARK: Helpers

  /// Hands an Open answer to the native core, which holds what it released
  /// until the coin it makes is checked. True when it was taken.
  private static func takeOpen(cardId: Data, answer: Data) -> Bool {
    let result = cardId.withUnsafeBytes { id in
      answer.withUnsafeBytes { a in
        ghost_wallet_java_card_take_open(
          id.bindMemory(to: UInt8.self).baseAddress,
          a.bindMemory(to: UInt8.self).baseAddress,
          UInt(a.count)
        )
      }
    }
    return result == 0
  }

  private static func hex(_ data: Data) -> String {
    data.map { String(format: "%02x", $0) }.joined()
  }

  private static func u32(_ value: UInt32) -> Data {
    Data([UInt8(value >> 24), UInt8((value >> 16) & 0xFF), UInt8((value >> 8) & 0xFF), UInt8(value & 0xFF)])
  }

  private static func stateName(_ state: UInt8) -> String {
    switch state {
    case 0: return "blank"
    case 1: return "sealed"
    case 2: return "opened"
    default: return "in an unknown state"
    }
  }
}
