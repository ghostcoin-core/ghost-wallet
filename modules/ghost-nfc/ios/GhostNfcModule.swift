// The card module as JavaScript sees it (modules/ghost-nfc/index.ts): the
// reader session, and the vault's operations. Every argument and result is
// public or encrypted: card UIDs, APDUs, MAC inputs and outputs, ciphertexts
// and the sealed Phantom Key. Keys and the Phantom Key stay in CardVault and
// the native core.
//
// The Seal relay (relayCheck, relayFill, relayFillConfirm and relayOpen,
// SealRelay.swift) carries a Sealed card's traffic between the card and the
// Seal natively: JavaScript gets only the result (the card's UID, the
// challenge, the Seal's signed answer, the time of each round trip and a
// Fill's public commit data), never a command or a card answer. The Open's
// phone key seed moves only between the native core and the Keychain
// (OpenKeyKeychain.swift).
//
// The Seal's attestation is fetched natively (fetchSealAttestation,
// SealAttestation.swift): JavaScript gets the attestation bytes and the hash
// of the certificate the connection presented, and sets the relay's pin
// (setSealPin) only after the native core verified the attestation. It
// hands the relay the ordered list of live Seal regions (setSealRegions);
// the relay, not JavaScript, chooses each card's home region from it.
import ExpoModulesCore

public final class GhostNfcModule: Module {
  private let reader = TagReader()
  private let vault = CardVault()
  private lazy var relay = SealRelay(reader: reader)
  private let attestation = SealAttestation()
  private lazy var javaCard = JavaCard(reader: reader)

  public func definition() -> ModuleDefinition {
    Name("GhostNfc")

    Function("isSupported") { () -> Bool in
      TagReader.available
    }

    AsyncFunction("beginSession") { (alert: String, promise: Promise) in
      self.reader.begin(alert: alert, promise: promise)
    }

    AsyncFunction("transceive") { (apdu: Data, promise: Promise) in
      self.reader.transceive(apdu, promise: promise)
    }

    Function("endSession") { (alert: String?, error: String?) in
      self.reader.end(alert: alert, error: error)
    }

    // A Ghost Java card (JavaCard.swift): each flow runs natively in one
    // tap, and resolves with public parts only, as hex. An Open's answer goes
    // to the native core, never here.
    AsyncFunction("javaCardCheck") { (alert: String, challenge: Data, confirmation: Data?, commitData: Bool, promise: Promise) in
      self.javaCard.check(alert: alert, challenge: challenge, confirmation: confirmation, commitData: commitData, promise: promise)
    }

    // `make` is Make's input: amount 12, chain id 8, writer nonce 32, open-code hash 32.
    AsyncFunction("javaCardFill") { (alert: String, make: Data, challenge: Data, confirmation: Data, promise: Promise) in
      self.javaCard.fill(alert: alert, make: make, challenge: challenge, confirmation: confirmation, promise: promise)
    }

    AsyncFunction("javaCardOpen") {
      (alert: String, code: Data, checkChallenge: Data, confirmation: Data, openChallenge: Data, promise: Promise) in
      self.javaCard.open(
        alert: alert, code: code, checkChallenge: checkChallenge, confirmation: confirmation, openChallenge: openChallenge,
        promise: promise)
    }

    AsyncFunction("javaCardRefill") { (alert: String, code: Data, promise: Promise) in
      self.javaCard.refill(alert: alert, code: code, promise: promise)
    }

    AsyncFunction("relayCheck") { (sealUrl: String, alert: String, promise: Promise) in
      self.relay.check(sealUrl: sealUrl, alert: alert, promise: promise)
    }

    // A Sealed card's Fill (and its confirmation) and Open through the Seal.
    // The PIN goes to the Seal in the start request only; an Open's release
    // goes to the native core, never back to JavaScript.
    AsyncFunction("relayFill") { (sealUrl: String, alert: String, amountWei: String, pin: String, promise: Promise) in
      self.relay.run(.fill(amountWei: amountWei, pin: pin), sealUrl: sealUrl, alert: alert, promise: promise)
    }

    AsyncFunction("relayFillConfirm") { (sealUrl: String, alert: String, promise: Promise) in
      self.relay.run(.fillConfirm, sealUrl: sealUrl, alert: alert, promise: promise)
    }

    AsyncFunction("relayOpen") { (sealUrl: String, alert: String, phoneKey: String, pin: String, promise: Promise) in
      self.relay.run(.open(phoneKey: phoneKey, pin: pin), sealUrl: sealUrl, alert: alert, promise: promise)
    }

    // The Seal's attestation (SealAttestation.swift): the attestation bytes
    // and the hash of the certificate the connection presented, nothing else.
    AsyncFunction("fetchSealAttestation") { (sealUrl: String, challenge: String, promise: Promise) in
      self.attestation.fetch(sealUrl: sealUrl, challenge: challenge, promise: promise)
    }

    // The relay's pinned certificate, set only after the core verified the
    // attestation that binds it; "" drops it.
    Function("setSealPin") { (sealUrl: String, certSha256: String) in
      SealPins.shared.set(sealUrl: sealUrl, certSha256: certSha256)
    }

    // The ordered list of live Seal regions, `[{ id, url }]` as JSON, kept in
    // memory for the relay to choose each card's home region from. A list
    // that does not parse clears it and returns false.
    Function("setSealRegions") { (regionsJson: String) -> Bool in
      SealRegions.shared.set(json: regionsJson)
    }

    // The Open's phone key seed, between the native core and the Keychain.
    Function("keepOpenKey") { () throws in
      try OpenKeyKeychain.keep()
    }

    Function("restoreOpenKey") { () throws -> Bool in
      try OpenKeyKeychain.restore()
    }

    Function("forgetOpenKey") {
      OpenKeyKeychain.forget()
    }

    Function("authPart2") { (uid: String, set: String, keyNo: Int, encryptedRndB: Data) throws -> Data in
      try self.vault.authPart2(uid: uid, set: set, keyNo: keyNo, encryptedRndB: encryptedRndB)
    }

    Function("authFinish") { (encryptedResponse: Data) throws -> Data in
      try self.vault.authFinish(encryptedResponse)
    }

    Function("cmac") { (input: Data) throws -> Data in
      try self.vault.cmac(input)
    }

    Function("encryptPadded") { (ivInput: Data, padded: Data) throws -> Data in
      try self.vault.encryptPadded(ivInput: ivInput, padded: padded)
    }

    Function("encryptChangeKey") { (ivInput: Data, keyNo: Int, to: String, from: String, version: Int) throws -> Data in
      try self.vault.encryptChangeKey(ivInput: ivInput, keyNo: keyNo, to: to, from: from, version: version)
    }

    Function("decrypt") { (ivInput: Data, ciphertext: Data) throws -> Data in
      try self.vault.decrypt(ivInput: ivInput, ciphertext: ciphertext)
    }

    Function("endVaultSession") {
      self.vault.endSession()
    }

    Function("hasKeys") { (uid: String) throws -> Bool in
      try self.vault.hasKeys(uid)
    }

    Function("makeKeys") { (uid: String) throws in
      try self.vault.makeKeys(uid)
    }

    Function("forgetKeys") { (uid: String) throws in
      try self.vault.forgetKeys(uid)
    }

    Function("sealPhantomKey") { (uid: String) throws -> Data in
      try self.vault.sealPhantomKey(uid)
    }

    Function("openPhantomKey") { (uid: String, sealed: Data) throws in
      try self.vault.openPhantomKey(uid, sealed: sealed)
    }
  }
}
