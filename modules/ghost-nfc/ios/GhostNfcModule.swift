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
import ExpoModulesCore

public final class GhostNfcModule: Module {
  private let reader = TagReader()
  private let vault = CardVault()
  private lazy var relay = SealRelay(reader: reader)

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
