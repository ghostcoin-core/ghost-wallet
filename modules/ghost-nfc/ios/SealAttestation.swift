// The Seal's attestation, fetched natively (docs/seal-app-attestation.md).
//
// One HTTPS `POST /v1/attestation` with `{ "challenge": "<64 hex>" }` to the
// Seal, on its own ephemeral URLSession whose delegate, for this one request
// only, takes the server's leaf certificate, hashes its DER with SHA-256 and
// lets the connection go on without trusting any name: the Seal's
// certificate is trusted only once the native core has checked that the
// Nitro attestation binds this very hash. JavaScript gets back only the
// attestation bytes and that hash, as hex. The request has a 10 second
// timeout and the answer is capped at 32 KiB. Nothing here logs.
//
// A failure rejects with one short code per cause (`SealAttestationFailure`):
// a network error with its `URLError` code number, an HTTP status other than
// 200 with that status, no leaf certificate captured, an answer too long, an
// answer that does not parse, or a bad challenge (a bad address is
// `SealAddressException`). The code holds nothing else: no byte of the
// answer, the challenge or the certificate.
//
// The relay (SealRelay.swift) then connects to the Seal only when its leaf
// certificate's hash equals the pin JavaScript set after the core's check
// (`SealPins`).
import CryptoKit
import ExpoModulesCore
import Foundation
import Security

/// Why the Seal's attestation could not be fetched: one cause, with at most a number.
enum SealAttestationFailure {
  /// The request failed: the `URLError` code number (for example -1200).
  case network(Int)
  /// The Seal answered with an HTTP status other than 200.
  case status(Int)
  /// The connection presented no leaf certificate to hash.
  case noLeaf
  /// The answer is longer than `SealAttestation.maxBytes`.
  case tooLong
  /// The answer holds no attestation.
  case parse
  /// The challenge is not 64 hex digits.
  case badChallenge

  /// The code JavaScript reads (modules/ghost-nfc/relay.ts).
  var code: String {
    switch self {
    case .network(let number): return "ERR_SEAL_ATTEST_NETWORK:\(number)"
    case .status(let number): return "ERR_SEAL_ATTEST_STATUS:\(number)"
    case .noLeaf: return "ERR_SEAL_ATTEST_NO_LEAF"
    case .tooLong: return "ERR_SEAL_ATTEST_TOO_LONG"
    case .parse: return "ERR_SEAL_ATTEST_PARSE"
    case .badChallenge: return "ERR_SEAL_ATTEST_BAD_CHALLENGE"
    }
  }
}

final class SealAttestationException: Exception {
  let failure: SealAttestationFailure

  init(_ failure: SealAttestationFailure, file: String = #fileID, line: UInt = #line, function: String = #function) {
    self.failure = failure
    super.init(file: file, line: line, function: function)
  }

  override var code: String { failure.code }
  override var reason: String { "The Seal's attestation could not be fetched (\(failure.code))." }
}

/// The SHA-256 of the DER of a connection's leaf certificate.
enum SealCertificates {
  static func leafSha256(_ trust: SecTrust) -> Data? {
    guard let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate], let leaf = chain.first else {
      return nil
    }
    let der = SecCertificateCopyData(leaf) as Data
    return Data(SHA256.hash(data: der))
  }
}

final class SealAttestation {
  /// The longest answer taken, in bytes.
  static let maxBytes = 32 * 1024
  /// The request's timeout, in seconds.
  static let timeoutSeconds: TimeInterval = 10

  /// Fetches the attestation for `challenge` (64 hex digits) from the Seal at `sealUrl`.
  func fetch(sealUrl: String, challenge: String, promise: Promise) {
    guard let url = Self.attestationUrl(sealUrl) else {
      promise.reject(SealAddressException())
      return
    }
    guard challenge.count == 64, challenge.allSatisfy({ $0.isHexDigit }) else {
      promise.reject(SealAttestationException(.badChallenge))
      return
    }
    let config = URLSessionConfiguration.ephemeral
    config.timeoutIntervalForRequest = 10
    config.timeoutIntervalForResource = 10
    config.requestCachePolicy = .reloadIgnoringLocalCacheData
    config.urlCache = nil
    config.httpCookieStorage = nil
    config.httpShouldSetCookies = false
    config.httpMaximumConnectionsPerHost = 1
    let capture = LeafCapture(promise: promise)
    let session = URLSession(configuration: config, delegate: capture, delegateQueue: nil)
    var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: Self.timeoutSeconds)
    request.httpMethod = "POST"
    request.setValue("application/json", forHTTPHeaderField: "Content-Type")
    request.httpBody = try? JSONSerialization.data(withJSONObject: ["challenge": challenge.lowercased()])
    session.dataTask(with: request).resume()
    // The session lets go of its delegate once this one request is over.
    session.finishTasksAndInvalidate()
  }

  /// `<sealUrl>/v1/attestation`, for an https:// address only.
  private static func attestationUrl(_ text: String) -> URL? {
    let trimmed = text.trimmingCharacters(in: .whitespaces)
    guard let base = URL(string: trimmed.hasSuffix("/") ? trimmed : trimmed + "/"),
          base.scheme?.lowercased() == "https", base.host != nil
    else { return nil }
    return base.appendingPathComponent("v1/attestation")
  }
}

/// The delegate of one attestation request: it measures the leaf
/// certificate the connection presented and collects at most 32 KiB.
private final class LeafCapture: NSObject, URLSessionDataDelegate {
  private let promise: Promise
  private let lock = NSLock()
  private var leafSha256: Data?
  private var body = Data()
  private var status = 0
  private var settled = false
  /// The server's trust challenge gave no leaf certificate to hash.
  private var leafMissing = false
  /// The answer was, or said it would be, longer than the cap.
  private var overLong = false

  init(promise: Promise) {
    self.promise = promise
  }

  func urlSession(
    _ session: URLSession,
    didReceive challenge: URLAuthenticationChallenge,
    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
  ) {
    capture(challenge, completionHandler)
  }

  func urlSession(
    _ session: URLSession,
    task: URLSessionTask,
    didReceive challenge: URLAuthenticationChallenge,
    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
  ) {
    capture(challenge, completionHandler)
  }

  /// Takes the leaf certificate's hash and lets this one connection go on;
  /// whether that certificate is the Seal's is the core's check.
  private func capture(
    _ challenge: URLAuthenticationChallenge,
    _ completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
  ) {
    guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
          let trust = challenge.protectionSpace.serverTrust,
          let hash = SealCertificates.leafSha256(trust)
    else {
      if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust {
        lock.lock()
        leafMissing = true
        lock.unlock()
      }
      completionHandler(.cancelAuthenticationChallenge, nil)
      return
    }
    lock.lock()
    leafSha256 = hash
    lock.unlock()
    completionHandler(.useCredential, URLCredential(trust: trust))
  }

  func urlSession(
    _ session: URLSession,
    dataTask: URLSessionDataTask,
    didReceive response: URLResponse,
    completionHandler: @escaping (URLSession.ResponseDisposition) -> Void
  ) {
    let code = (response as? HTTPURLResponse)?.statusCode ?? 0
    let tooLong = response.expectedContentLength > Int64(SealAttestation.maxBytes)
    lock.lock()
    status = code
    if tooLong {
      overLong = true
    }
    lock.unlock()
    completionHandler(code == 200 && !tooLong ? .allow : .cancel)
  }

  func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
    lock.lock()
    body.append(data)
    let tooLong = body.count > SealAttestation.maxBytes
    if tooLong {
      overLong = true
    }
    lock.unlock()
    if tooLong {
      dataTask.cancel()
    }
  }

  func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
    lock.lock()
    let first = !settled
    settled = true
    let captured = leafSha256
    let answer = body
    let code = status
    let noLeaf = leafMissing
    let tooLong = overLong || answer.count > SealAttestation.maxBytes
    body = Data()
    lock.unlock()
    guard first else { return }
    if let failure = Self.failure(error: error, status: code, noLeaf: noLeaf, tooLong: tooLong, leaf: captured != nil) {
      promise.reject(SealAttestationException(failure))
      return
    }
    guard let hash = captured, let attestation = Self.attestation(answer), !attestation.isEmpty else {
      promise.reject(SealAttestationException(.parse))
      return
    }
    promise.resolve(["attestation": Self.hex(attestation), "certSha256": Self.hex(hash)])
  }

  /// Why the request gave no answer to parse, or nil. A cancel of this
  /// delegate's own (no leaf, too long, a status other than 200) is named for
  /// its cause, not as the network error it ends with.
  private static func failure(error: Error?, status: Int, noLeaf: Bool, tooLong: Bool, leaf: Bool) -> SealAttestationFailure? {
    if noLeaf {
      return .noLeaf
    }
    if tooLong {
      return .tooLong
    }
    if status != 0 && status != 200 {
      return .status(status)
    }
    if let error = error {
      return .network((error as NSError).code)
    }
    if status != 200 {
      return .status(status)
    }
    if !leaf {
      return .noLeaf
    }
    return nil
  }

  /// The answer's attestation: the raw `GPA2` bytes, or JSON `{ "attestation": "<hex>" }`.
  private static func attestation(_ answer: Data) -> Data? {
    if answer.starts(with: Data("GPA2".utf8)) {
      return answer
    }
    guard let fields = (try? JSONSerialization.jsonObject(with: answer)) as? [String: Any],
          let text = fields["attestation"] as? String
    else { return nil }
    return bytes(text)
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
