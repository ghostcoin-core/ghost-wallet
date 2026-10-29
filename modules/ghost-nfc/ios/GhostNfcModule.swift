// The card module as JavaScript sees it (modules/ghost-nfc/index.ts): the
// reader session, and the vault's operations. Every argument and result is
// public or encrypted: card UIDs, APDUs, MAC inputs and outputs, ciphertexts
// and the sealed Phantom Key. Keys and the Phantom Key stay in CardVault and
// the native core.
import ExpoModulesCore

public final class GhostNfcModule: Module {
  private let reader = TagReader()
  private let vault = CardVault()

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
