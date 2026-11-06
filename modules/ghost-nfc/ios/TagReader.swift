// One Core NFC reader session at a time: it waits for an ISO 7816 tag (the
// NTAG 424 DNA's NDEF application, listed in the app's select identifiers),
// connects, and passes APDUs to it. It holds no secret: the APDUs it carries
// are public or already encrypted.
//
// The card code in JavaScript drives it through promises (begin, transceive,
// end); the Seal relay (SealRelay.swift) drives it natively through the
// callback forms (begin with the card's UID, send), so the relayed card
// traffic never reaches JavaScript.
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
  /// Called once, on `queue`, with the connected card's UID or why there is none.
  private var connected: ((Result<Data, Exception>) -> Void)?

  static var available: Bool { NFCTagReaderSession.readingAvailable }

  func begin(alert: String, promise: Promise) {
    begin(alert: alert) { result in
      switch result {
      case .success:
        promise.resolve(nil)
      case let .failure(error):
        promise.reject(error)
      }
    }
  }

  /// Opens a reader session and calls back (on the reader's queue) with the
  /// UID of the ISO 7816 tag it connected to, or the reason it could not.
  func begin(alert: String, onConnected: @escaping (Result<Data, Exception>) -> Void) {
    queue.async {
      guard Self.available else {
        onConnected(.failure(NfcUnavailableException()))
        return
      }
      self.close(alert: nil, error: nil)
      self.connected = onConnected
      guard let session = NFCTagReaderSession(pollingOption: [.iso14443], delegate: self, queue: self.queue) else {
        self.connected = nil
        onConnected(.failure(NfcUnavailableException()))
        return
      }
      session.alertMessage = alert
      self.session = session
      session.begin()
    }
  }

  func transceive(_ apdu: Data, promise: Promise) {
    send(apdu) { answer in
      if let answer {
        promise.resolve(answer)
      } else {
        promise.reject(NfcSessionException())
      }
    }
  }

  /// Sends one APDU to the connected card and calls back (on the reader's
  /// queue) with its raw answer, data then SW1 SW2, or nil when the card is
  /// gone. The bytes are passed as they are: nothing here reads them.
  func send(_ apdu: Data, completion: @escaping (Data?) -> Void) {
    queue.async {
      guard let tag = self.tag, let command = NFCISO7816APDU(data: apdu) else {
        completion(nil)
        return
      }
      tag.sendCommand(apdu: command) { data, sw1, sw2, error in
        self.queue.async {
          if error != nil {
            completion(nil)
            return
          }
          var answer = data
          answer.append(sw1)
          answer.append(sw2)
          completion(answer)
        }
      }
    }
  }

  /// Changes the message on the card sheet.
  func update(alert: String) {
    queue.async {
      self.session?.alertMessage = alert
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
    if let onConnected = connected {
      connected = nil
      let cancelled = (error as? NFCReaderError)?.code == .readerSessionInvalidationErrorUserCanceled
      onConnected(.failure(cancelled ? NfcCancelledException() : NfcSessionException()))
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
        self.connected?(.success(iso.identifier))
        self.connected = nil
      }
    }
  }
}
