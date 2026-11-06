// The Seal relay (docs/seal-relay.md): the phone carries the Seal's card
// traffic. It opens the NFC session (TagReader) and a connection to the Seal
// (URLSession), starts a Check, a Fill, a Fill's confirmation or an Open
// with the card's UID and a fresh 32-byte challenge, then passes each command
// from the Seal to the card and each answer from the card back to the Seal,
// as opaque bytes, until the Seal's signed answer comes back.
//
// It never decrypts the traffic and holds no card key: the card's secure
// messaging runs between the chip and the Seal. Nothing here hands the
// traffic to JavaScript either: the only result is the card's UID, the
// challenge, the Seal's signed answer, the time of each round trip and, for
// a Fill, the coin's public commit data. An Open's release package (the
// card's key, encrypted to the native core's phone key) goes straight to the
// native core (ghost_wallet_seal_open_take_release), never to JavaScript.
// An Open PIN is sent to the Seal in the start request only and kept nowhere.
//
// The relay connects only to a Seal whose certificate is pinned (`SealPins`,
// docs/seal-app-attestation.md): JavaScript sets the pin, the SHA-256 of the
// leaf certificate's DER, only after the native core verified the Seal's
// Nitro attestation that binds it. Every connection's leaf certificate is
// hashed and compared with the pin of its host; with no pin, another hash or
// no TLS at all, the connection is cancelled and the flow fails as
// "seal-unreachable". Nothing here logs.
import ExpoModulesCore
import Foundation
import Security

final class SealAddressException: Exception {
  override var reason: String { "The Seal address must be an https:// address." }
}

/// The certificate each Seal host is pinned to (memory only). Set only by
/// `setSealPin` after the core's check of the attestation; an empty hash
/// drops it.
final class SealPins {
  static let shared = SealPins()

  private let lock = NSLock()
  private var pins: [String: Data] = [:]

  /// Pins the host of `sealUrl` to `certSha256` (64 hex digits), or drops its pin for anything else.
  func set(sealUrl: String, certSha256: String) {
    guard let url = URL(string: sealUrl.trimmingCharacters(in: .whitespaces)),
          url.scheme?.lowercased() == "https", let host = url.host
    else { return }
    let key = Self.key(host: host, port: url.port ?? 443)
    let hash = certSha256.count == 64 ? Self.bytes(certSha256) : nil
    lock.lock()
    pins[key] = hash
    lock.unlock()
  }

  /// The pinned hash of `host` and `port`, if any.
  func pinned(host: String, port: Int) -> Data? {
    lock.lock()
    defer { lock.unlock() }
    return pins[Self.key(host: host, port: port > 0 ? port : 443)]
  }

  /// Whether `url` may be connected to at all: https:// with a pin for its host.
  func allows(_ url: URL) -> Bool {
    guard url.scheme?.lowercased() == "https", let host = url.host else { return false }
    return pinned(host: host, port: url.port ?? 443) != nil
  }

  private static func key(host: String, port: Int) -> String {
    "\(host.lowercased()):\(port)"
  }

  private static func bytes(_ hex: String) -> Data? {
    let digits = Array(hex.utf8)
    guard digits.count % 2 == 0 else { return nil }
    var out = Data(capacity: digits.count / 2)
    var index = 0
    while index < digits.count {
      guard let byte = UInt8(String(decoding: digits[index..<index + 2], as: UTF8.self), radix: 16) else { return nil }
      out.append(byte)
      index += 2
    }
    return out
  }
}

/// The relay's connection check: a connection goes on only when its leaf
/// certificate's SHA-256 equals the pin of its host; otherwise it is cancelled.
private final class PinnedSealTrust: NSObject, URLSessionDelegate, URLSessionTaskDelegate {
  func urlSession(
    _ session: URLSession,
    didReceive challenge: URLAuthenticationChallenge,
    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
  ) {
    check(challenge, completionHandler)
  }

  func urlSession(
    _ session: URLSession,
    task: URLSessionTask,
    didReceive challenge: URLAuthenticationChallenge,
    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
  ) {
    check(challenge, completionHandler)
  }

  private func check(
    _ challenge: URLAuthenticationChallenge,
    _ completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
  ) {
    let space = challenge.protectionSpace
    guard space.authenticationMethod == NSURLAuthenticationMethodServerTrust,
          let trust = space.serverTrust,
          let pinned = SealPins.shared.pinned(host: space.host, port: space.port),
          let presented = SealCertificates.leafSha256(trust),
          presented == pinned
    else {
      completionHandler(.cancelAuthenticationChallenge, nil)
      return
    }
    completionHandler(.useCredential, URLCredential(trust: trust))
  }
}

final class SealRelayBusyException: Exception {
  override var reason: String { "A Check is already running." }
}

final class SealUnreachableException: Exception {
  override var reason: String { "The Seal could not be reached. Check the address and the network." }
}

final class SealExpiredException: Exception {
  override var reason: String { "The Seal stopped waiting for the card. Tap the card again." }
}

final class SealRefusedException: GenericException<String> {
  override var reason: String { "The Seal refused the card: \(param)" }
}

final class SealBadAnswerException: Exception {
  override var reason: String { "The Seal's answer is not an answer of this flow about this card." }
}

final class SealNotGhostCardException: Exception {
  override var reason: String { "Not a Ghost card." }
}

final class SealFillingException: Exception {
  override var reason: String { "The card is filling, waiting for its payment to settle." }
}

final class SealCantCheckException: Exception {
  override var reason: String { "The Seal cannot check the chain right now." }
}

final class SealPinRequiredException: Exception {
  override var reason: String { "This card needs its PIN to open." }
}

final class SealWrongPinException: Exception {
  override var reason: String { "Wrong PIN." }
}

final class SealPinLockedException: Exception {
  override var reason: String { "This card is locked: its PIN has no tries left." }
}

final class SealSpentException: Exception {
  override var reason: String { "This card was emptied." }
}

final class SealWrongStateException: Exception {
  override var reason: String { "This card cannot do that now." }
}

final class SealFillPendingException: Exception {
  override var reason: String { "This card is already being filled with another amount or PIN." }
}

final class SealRelay {
  /// The signed answer's layout (seal/src/answer.rs).
  private static let answerDomain = Data("ghost-seal/v1/answer".utf8)
  private static let answerBytes = 203
  /// A coin's commit data (core/src/vanish.rs).
  private static let commitDataBytes = 430
  /// The longest release package (core/src/seal_open.rs).
  private static let maxReleaseBytes = 1220
  /// Stay inside the iOS NFC session limit of 60 seconds.
  private static let maxSeconds = 50.0

  /// What the relay runs: its start path, its answer kind and how many card round trips it may take.
  enum Flow {
    case check
    case fill(amountWei: String, pin: String)
    case fillConfirm
    case open(phoneKey: String, pin: String)

    var path: String {
      switch self {
      case .check: return "v1/check/start"
      case .fill: return "v1/fill/start"
      case .fillConfirm: return "v1/fill/confirm"
      case .open: return "v1/open/start"
      }
    }

    /// 1 Check, 2 Fill (and its confirmation), 3 Open.
    var kind: UInt8 {
      switch self {
      case .check: return 1
      case .fill, .fillConfirm: return 2
      case .open: return 3
      }
    }

    /// A Check is about seven card round trips; an Open rotates five keys and
    /// authenticates with each new one. Anything far past that is refused.
    var maxSteps: Int {
      switch self {
      case .check: return 32
      case .fill, .fillConfirm: return 64
      case .open: return 160
      }
    }

    var working: String {
      switch self {
      case .check: return "Checking the card with the Seal…"
      case .fill: return "Filling the card with the Seal…"
      case .fillConfirm: return "Checking the card's payment with the Seal…"
      case .open: return "Opening the card with the Seal…"
      }
    }

    var done: String {
      switch self {
      case .check, .fillConfirm: return "Card checked."
      case .fill: return "The card holds a new key."
      case .open: return "Card opened."
      }
    }

    func startBody(uid: Data, challenge: Data) -> [String: String] {
      var body = ["uid": SealRelay.hex(uid), "challenge": SealRelay.hex(challenge)]
      switch self {
      case .check, .fillConfirm:
        break
      case let .fill(amountWei, pin):
        body["amountWei"] = amountWei
        if !pin.isEmpty { body["pin"] = pin }
      case let .open(phoneKey, pin):
        body["phoneKey"] = phoneKey
        if !pin.isEmpty { body["pin"] = pin }
      }
      return body
    }
  }

  private let reader: TagReader
  private let queue = DispatchQueue(label: "com.ghostcoin.wallet.seal-relay")
  private let http: URLSession
  private var running = false

  init(reader: TagReader) {
    self.reader = reader
    let config = URLSessionConfiguration.ephemeral
    config.timeoutIntervalForRequest = 10
    config.timeoutIntervalForResource = 30
    config.requestCachePolicy = .reloadIgnoringLocalCacheData
    config.urlCache = nil
    config.httpCookieStorage = nil
    config.httpShouldSetCookies = false
    http = URLSession(configuration: config, delegate: PinnedSealTrust(), delegateQueue: nil)
  }

  /// Runs one Check through the Seal at `sealUrl` on the next card tapped.
  func check(sealUrl: String, alert: String, promise: Promise) {
    run(.check, sealUrl: sealUrl, alert: alert, promise: promise)
  }

  /// Runs `flow` through the Seal at `sealUrl` on the next card tapped.
  func run(_ flow: Flow, sealUrl: String, alert: String, promise: Promise) {
    queue.async {
      guard let base = Self.baseUrl(sealUrl) else {
        promise.reject(SealAddressException())
        return
      }
      guard !self.running else {
        promise.reject(SealRelayBusyException())
        return
      }
      // No pinned certificate for this Seal: no connection at all.
      guard SealPins.shared.allows(base) else {
        promise.reject(SealUnreachableException())
        return
      }
      guard let challenge = Self.randomBytes(32) else {
        promise.reject(SealUnreachableException())
        return
      }
      self.running = true
      let run = Run(flow: flow, base: base, challenge: challenge, promise: promise)
      self.reader.begin(alert: alert) { result in
        self.queue.async {
          switch result {
          case let .failure(error):
            self.finish(run, error: error)
          case let .success(uid):
            run.uid = uid
            run.started = DispatchTime.now().uptimeNanoseconds
            self.reader.update(alert: flow.working)
            self.post(run, path: flow.path, body: flow.startBody(uid: uid, challenge: challenge))
          }
        }
      }
    }
  }

  // MARK: The relay loop (on `queue`)

  private final class Run {
    let flow: Flow
    let base: URL
    let challenge: Data
    let promise: Promise
    var uid = Data()
    var session: String?
    var started: UInt64 = 0
    var steps = 0
    var rounds: [[String: Any]] = []

    init(flow: Flow, base: URL, challenge: Data, promise: Promise) {
      self.flow = flow
      self.base = base
      self.challenge = challenge
      self.promise = promise
    }

    var elapsedMs: Double { Double(DispatchTime.now().uptimeNanoseconds - started) / 1_000_000 }
  }

  private func post(_ run: Run, path: String, body: [String: String]) {
    guard run.elapsedMs < Self.maxSeconds * 1000 else {
      finish(run, error: SealExpiredException())
      return
    }
    guard SealPins.shared.allows(run.base) else {
      finish(run, error: SealUnreachableException())
      return
    }
    var request = URLRequest(url: run.base.appendingPathComponent(path))
    request.httpMethod = "POST"
    request.setValue("application/json", forHTTPHeaderField: "Content-Type")
    request.httpBody = try? JSONSerialization.data(withJSONObject: body)
    let sent = DispatchTime.now().uptimeNanoseconds
    http.dataTask(with: request) { data, response, error in
      self.queue.async {
        run.rounds.append(["kind": "seal", "ms": Self.since(sent)])
        guard error == nil, let data, let status = (response as? HTTPURLResponse)?.statusCode,
              let fields = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
        else {
          self.finish(run, error: SealUnreachableException())
          return
        }
        guard status == 200 else {
          self.finish(run, error: Self.refusal(fields))
          return
        }
        self.handle(run, fields)
      }
    }.resume()
  }

  private func handle(_ run: Run, _ fields: [String: Any]) {
    switch fields["status"] as? String {
    case "apdu":
      run.steps += 1
      guard run.steps <= run.flow.maxSteps, let session = fields["session"] as? String,
            let command = (fields["apdu"] as? String).flatMap(Self.bytes)
      else {
        finish(run, error: SealBadAnswerException())
        return
      }
      run.session = session
      let sent = DispatchTime.now().uptimeNanoseconds
      reader.send(command) { answer in
        self.queue.async {
          run.rounds.append(["kind": "card", "ms": Self.since(sent)])
          guard let answer else {
            self.abort(run)
            self.finish(run, error: NfcSessionException())
            return
          }
          self.post(run, path: "v1/relay/step", body: ["session": session, "answer": Self.hex(answer)])
        }
      }
    case "done":
      guard let answer = (fields["answer"] as? String).flatMap(Self.bytes),
            let signature = (fields["signature"] as? String).flatMap(Self.bytes),
            Self.isAnswer(answer, kind: run.flow.kind, challenge: run.challenge, uid: run.uid)
      else {
        finish(run, error: SealBadAnswerException())
        return
      }
      var result: [String: Any] = [
        "uid": Self.hex(run.uid),
        "challenge": Self.hex(run.challenge),
        "answer": Self.hex(answer),
        "signature": Self.hex(signature),
        "rounds": run.rounds,
        "totalMs": run.elapsedMs,
      ]
      switch run.flow {
      case .fill:
        guard let commitData = (fields["commitData"] as? String).flatMap(Self.bytes),
              commitData.count == Self.commitDataBytes
        else {
          finish(run, error: SealBadAnswerException())
          return
        }
        result["commitData"] = Self.hex(commitData)
      case .open:
        // The release goes to the native core only; it is wiped here once handed over.
        guard var release = (fields["release"] as? String).flatMap(Self.bytes),
              release.count <= Self.maxReleaseBytes
        else {
          finish(run, error: SealBadAnswerException())
          return
        }
        let held = release.withUnsafeBytes { bytes in
          ghost_wallet_seal_open_take_release(bytes.bindMemory(to: UInt8.self).baseAddress, UInt(bytes.count))
        }
        CardCrypto.wipe(&release)
        guard held == 0 else {
          finish(run, error: SealBadAnswerException())
          return
        }
      case .check, .fillConfirm:
        break
      }
      reader.end(alert: run.flow.done, error: nil)
      running = false
      run.promise.resolve(result)
    default:
      finish(run, error: SealBadAnswerException())
    }
  }

  /// Tells the Seal the card left the field. Best effort: the session times
  /// out on the Seal anyway.
  private func abort(_ run: Run) {
    guard let session = run.session else { return }
    var request = URLRequest(url: run.base.appendingPathComponent("v1/relay/abort"))
    request.httpMethod = "POST"
    request.setValue("application/json", forHTTPHeaderField: "Content-Type")
    request.httpBody = try? JSONSerialization.data(withJSONObject: ["session": session])
    http.dataTask(with: request) { _, _, _ in }.resume()
  }

  private func finish(_ run: Run, error: Exception) {
    let cancelled = error is NfcCancelledException || error is NfcUnavailableException
    reader.end(alert: nil, error: cancelled ? nil : error.reason)
    running = false
    run.promise.reject(error)
  }

  // MARK: Helpers

  /// Whether `answer` is an answer of `kind` over this challenge about this
  /// card. The state and amount are read from these signed bytes, never from
  /// unsigned fields; the signature itself is checked by the native core.
  private static func isAnswer(_ answer: Data, kind: UInt8, challenge: Data, uid: Data) -> Bool {
    let bytes = [UInt8](answer)
    guard bytes.count == answerBytes, uid.count == 7 else { return false }
    return Data(bytes[0..<20]) == answerDomain
      && bytes[20] == kind
      && Data(bytes[21..<53]) == challenge
      && Data(bytes[53..<60]) == uid
  }

  /// The Seal's refusal, by its `reason` code (docs/seal-relay.md); the
  /// message is never shown as is.
  private static func refusal(_ fields: [String: Any]) -> Exception {
    switch fields["error"] as? String {
    case "expired":
      return SealExpiredException()
    case "card-dropped":
      return NfcSessionException()
    default:
      break
    }
    switch fields["reason"] as? String {
    case "not-a-ghost-card": return SealNotGhostCardException()
    case "filling", "not-paid": return SealFillingException()
    case "cant-check-now": return SealCantCheckException()
    case "pin-required": return SealPinRequiredException()
    case "wrong-pin": return SealWrongPinException()
    case "pin-locked": return SealPinLockedException()
    case "spent": return SealSpentException()
    case "wrong-state": return SealWrongStateException()
    case "fill-pending": return SealFillPendingException()
    default: return SealRefusedException((fields["message"] as? String) ?? "no reason given")
    }
  }

  private static func baseUrl(_ text: String) -> URL? {
    let trimmed = text.trimmingCharacters(in: .whitespaces)
    guard let url = URL(string: trimmed.hasSuffix("/") ? trimmed : trimmed + "/"),
          url.scheme?.lowercased() == "https",
          url.host != nil
    else { return nil }
    return url
  }

  private static func since(_ start: UInt64) -> Double {
    Double(DispatchTime.now().uptimeNanoseconds - start) / 1_000_000
  }

  private static func randomBytes(_ count: Int) -> Data? {
    var bytes = [UInt8](repeating: 0, count: count)
    guard SecRandomCopyBytes(kSecRandomDefault, count, &bytes) == errSecSuccess else { return nil }
    return Data(bytes)
  }

  fileprivate static func hex(_ data: Data) -> String {
    data.map { String(format: "%02x", $0) }.joined()
  }

  private static func bytes(_ hex: String) -> Data? {
    let digits = Array(hex.utf8)
    guard digits.count % 2 == 0 else { return nil }
    var out = Data(capacity: digits.count / 2)
    var index = 0
    while index < digits.count {
      guard let byte = UInt8(String(decoding: digits[index..<index + 2], as: UTF8.self), radix: 16) else { return nil }
      out.append(byte)
      index += 2
    }
    return out
  }
}
