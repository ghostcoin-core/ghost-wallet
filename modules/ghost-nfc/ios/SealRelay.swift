// The Seal relay (docs/seal-relay.md): the phone carries the Seal's card
// traffic. It opens the NFC session (TagReader) and a connection to the Seal
// (URLSession), starts a Check with the card's UID and a fresh 32-byte
// challenge, then passes each command from the Seal to the card and each
// answer from the card back to the Seal, as opaque bytes, until the Seal's
// signed answer comes back.
//
// It never decrypts the traffic and holds no card key: the card's secure
// messaging runs between the chip and the Seal. Nothing here hands the
// traffic to JavaScript either: the only result is the card's UID, the
// challenge, the Seal's signed answer and the time of each round trip.
import ExpoModulesCore
import Foundation
import Security

final class SealAddressException: Exception {
  override var reason: String { "The Seal address must be an https:// address (http:// only on this network)." }
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
  override var reason: String { "The Seal's answer is not a Check of this card." }
}

final class SealRelay {
  /// The signed answer's layout (seal/src/answer.rs).
  private static let answerDomain = Data("ghost-seal/v1/answer".utf8)
  private static let answerBytes = 203
  private static let kindCheck: UInt8 = 1
  /// A Check is about seven card round trips; anything far past that is not a Check.
  private static let maxSteps = 32
  /// Stay inside the iOS NFC session limit of 60 seconds.
  private static let maxSeconds = 50.0

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
    http = URLSession(configuration: config)
  }

  /// Runs one Check through the Seal at `sealUrl` on the next card tapped.
  func check(sealUrl: String, alert: String, promise: Promise) {
    queue.async {
      guard let base = Self.baseUrl(sealUrl) else {
        promise.reject(SealAddressException())
        return
      }
      guard !self.running else {
        promise.reject(SealRelayBusyException())
        return
      }
      guard let challenge = Self.randomBytes(32) else {
        promise.reject(SealUnreachableException())
        return
      }
      self.running = true
      let run = Run(base: base, challenge: challenge, promise: promise)
      self.reader.begin(alert: alert) { result in
        self.queue.async {
          switch result {
          case let .failure(error):
            self.finish(run, error: error)
          case let .success(uid):
            run.uid = uid
            run.started = DispatchTime.now().uptimeNanoseconds
            self.reader.update(alert: "Checking the card with the Seal…")
            self.post(run, path: "v1/check/start", body: ["uid": Self.hex(uid), "challenge": Self.hex(challenge)])
          }
        }
      }
    }
  }

  // MARK: The relay loop (on `queue`)

  private final class Run {
    let base: URL
    let challenge: Data
    let promise: Promise
    var uid = Data()
    var session: String?
    var started: UInt64 = 0
    var steps = 0
    var rounds: [[String: Any]] = []

    init(base: URL, challenge: Data, promise: Promise) {
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
      guard run.steps <= Self.maxSteps, let session = fields["session"] as? String,
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
            Self.isCheck(answer, challenge: run.challenge, uid: run.uid)
      else {
        finish(run, error: SealBadAnswerException())
        return
      }
      let result: [String: Any] = [
        "uid": Self.hex(run.uid),
        "challenge": Self.hex(run.challenge),
        "answer": Self.hex(answer),
        "signature": Self.hex(signature),
        "rounds": run.rounds,
        "totalMs": run.elapsedMs,
      ]
      reader.end(alert: "Card checked.", error: nil)
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

  /// Whether `answer` is a Check answer over this challenge about this card.
  /// The state and amount are read from these signed bytes, never from
  /// unsigned fields; the signature itself is checked by the Check screen.
  private static func isCheck(_ answer: Data, challenge: Data, uid: Data) -> Bool {
    let bytes = [UInt8](answer)
    guard bytes.count == answerBytes, uid.count == 7 else { return false }
    return Data(bytes[0..<20]) == answerDomain
      && bytes[20] == kindCheck
      && Data(bytes[21..<53]) == challenge
      && Data(bytes[53..<60]) == uid
  }

  private static func refusal(_ fields: [String: Any]) -> Exception {
    switch fields["error"] as? String {
    case "expired":
      return SealExpiredException()
    case "card-dropped":
      return NfcSessionException()
    default:
      return SealRefusedException((fields["message"] as? String) ?? "no reason given")
    }
  }

  private static func baseUrl(_ text: String) -> URL? {
    let trimmed = text.trimmingCharacters(in: .whitespaces)
    guard let url = URL(string: trimmed.hasSuffix("/") ? trimmed : trimmed + "/"),
          let scheme = url.scheme?.lowercased(), scheme == "https" || scheme == "http",
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

  private static func hex(_ data: Data) -> String {
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
