// One Core NFC reader session at a time: it waits for an ISO 7816 tag (the
// NTAG 424 DNA's NDEF application, listed in the app's select identifiers),
// connects, and passes APDUs to it. It holds no secret: the APDUs it carries
// are public or already encrypted.
import CoreNFC
import ExpoModulesCore

final class NfcUnavailableException: Exception {
  override var reason: String { "This iPhone cannot read NFC cards." }
}

final class NfcCancelledException: Exception {
  override var reason: String { "The card sheet was closed." }
}

final class NfcSessionException: Exception {
  override var reason: String { "The card could not be read. Hold it still and try again." }
}

final class TagReader: NSObject, NFCTagReaderSessionDelegate {
  private let queue = DispatchQueue(label: "com.ghostcoin.wallet.nfc")
  private var session: NFCTagReaderSession?
  private var tag: NFCISO7816Tag?
  private var connected: Promise?

  static var available: Bool { NFCTagReaderSession.readingAvailable }

  func begin(alert: String, promise: Promise) {
    queue.async {
      guard Self.available else {
        promise.reject(NfcUnavailableException())
        return
      }
      self.close(alert: nil, error: nil)
      self.connected = promise
      guard let session = NFCTagReaderSession(pollingOption: [.iso14443], delegate: self, queue: self.queue) else {
        self.connected = nil
        promise.reject(NfcUnavailableException())
        return
      }
      session.alertMessage = alert
      self.session = session
      session.begin()
    }
  }

  func transceive(_ apdu: Data, promise: Promise) {
    queue.async {
      guard let tag = self.tag, let command = NFCISO7816APDU(data: apdu) else {
        promise.reject(NfcSessionException())
        return
      }
      tag.sendCommand(apdu: command) { data, sw1, sw2, error in
        if error != nil {
          promise.reject(NfcSessionException())
          return
        }
        var answer = data
        answer.append(sw1)
        answer.append(sw2)
        promise.resolve(answer)
      }
    }
  }

  func end(alert: String?, error: String?) {
    queue.async {
      self.close(alert: alert, error: error)
    }
  }

  private func close(alert: String?, error: String?) {
    guard let session else { return }
    if let error {
      session.invalidate(errorMessage: error)
    } else {
      if let alert {
        session.alertMessage = alert
      }
      session.invalidate()
    }
    self.session = nil
    tag = nil
  }

  // MARK: NFCTagReaderSessionDelegate (called on `queue`)

  func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) {}

  func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
    guard session === self.session || self.session == nil else { return }
    if let promise = connected {
      connected = nil
      let cancelled = (error as? NFCReaderError)?.code == .readerSessionInvalidationErrorUserCanceled
      promise.reject(cancelled ? NfcCancelledException() : NfcSessionException())
    }
    if session === self.session {
      self.session = nil
      tag = nil
    }
  }

  func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
    guard session === self.session else { return }
    guard tags.count == 1, let first = tags.first, case let .iso7816(iso) = first else {
      session.alertMessage = "Hold one NTAG 424 card near the top of the iPhone."
      session.restartPolling()
      return
    }
    session.connect(to: first) { error in
      self.queue.async {
        guard session === self.session else { return }
        if error != nil {
          session.invalidate(errorMessage: "The card could not be read. Hold it still and try again.")
          return
        }
        self.tag = iso
        self.connected?.resolve(nil)
        self.connected = nil
      }
    }
  }
}
