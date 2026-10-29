// The secrets of a card tap: the card's keys (CardKeychain), the session keys
// of AuthenticateEV2First, and the Phantom Key going to or coming from the
// card. JavaScript frames the commands (modules/ghost-nfc/*.ts) and asks this
// vault for the operations that need a key; nothing it returns is a key or a
// Phantom Key. Nothing here logs.
import CryptoKit
import Foundation

enum CardVaultError: Error, CustomStringConvertible {
  case noKeys
  case noSession
  case noAuthentication
  case cardDidNotProve
  case unknownKey
  case noPhantomKey
  case notAPhantomKey
  case sealedBroken
  case malformed

  var description: String {
    switch self {
    case .noKeys: return "no keys are saved for this card"
    case .noSession: return "no card session is open"
    case .noAuthentication: return "no authentication is under way"
    case .cardDidNotProve: return "the card did not prove it holds the key"
    case .unknownKey: return "the app uses keys 0 and 2 only"
    case .noPhantomKey: return "no checked Phantom Key is held"
    case .notAPhantomKey: return "the card does not hold a Phantom Key"
    case .sealedBroken: return "the card's Phantom Key could not be opened"
    case .malformed: return "malformed input"
    }
  }
}

final class CardVault {
  private struct Pending {
    var key: Data
    let keyNo: Int
    var rndA: Data
    var rndB: Data
    let uid: String
  }

  private struct Session {
    var enc: Data
    var mac: Data
    let keyNo: Int
    let uid: String
  }

  private let lock = NSLock()
  private var pending: Pending?
  private var session: Session?

  /// Domain of the sealed Phantom Key, with the card's UID.
  private static let sealContext = Data("ghost-wallet card phantom key v1".utf8)
  /// Longest Phantom Key text the core hands out (24 words or the digits form).
  private static let maxKeyBytes = 512

  private func locked<T>(_ body: () throws -> T) rethrows -> T {
    lock.lock()
    defer { lock.unlock() }
    return try body()
  }

  private func cardKey(uid: String, set: String, keyNo: Int) throws -> Data {
    if set == "factory" {
      return CardCrypto.zeroBlock
    }
    guard set == "saved" else { throw CardVaultError.malformed }
    guard var keys = try CardKeychain.load(uid) else { throw CardVaultError.noKeys }
    defer { keys.wipe() }
    switch keyNo {
    case 0: return Data(keys.master)
    case 2: return Data(keys.file)
    default: throw CardVaultError.unknownKey
    }
  }

  // MARK: AuthenticateEV2First

  func authPart2(uid: String, set: String, keyNo: Int, encryptedRndB: Data) throws -> Data {
    try locked {
      guard encryptedRndB.count == 16 else { throw CardVaultError.malformed }
      clearSession()
      let key = try cardKey(uid: uid, set: set, keyNo: keyNo)
      let rndB = try CardCrypto.cbcDecrypt(key: key, iv: CardCrypto.zeroBlock, data: encryptedRndB)
      let rndA = try CardCrypto.random(16)
      pending = Pending(key: key, keyNo: keyNo, rndA: rndA, rndB: rndB, uid: uid)
      return try CardCrypto.cbcEncrypt(key: key, iv: CardCrypto.zeroBlock, data: rndA + CardCrypto.rotateLeft(rndB))
    }
  }

  /// SV1 / SV2 of the datasheet: label || 00 01 00 80 || RndA[0..1] || (RndA[2..7] ^ RndB[0..5]) || RndB[6..15] || RndA[8..15].
  private static func sessionVector(_ label: [UInt8], rndA: Data, rndB: Data) -> Data {
    let a = [UInt8](rndA)
    let b = [UInt8](rndB)
    var vector = label + [0x00, 0x01, 0x00, 0x80]
    vector += a[0..<2]
    vector += (0..<6).map { a[2 + $0] ^ b[$0] }
    vector += b[6..<16]
    vector += a[8..<16]
    return Data(vector)
  }

  func authFinish(_ encryptedResponse: Data) throws -> Data {
    try locked {
      guard var started = pending else { throw CardVaultError.noAuthentication }
      pending = nil
      defer {
        CardCrypto.wipe(&started.key)
        CardCrypto.wipe(&started.rndA)
        CardCrypto.wipe(&started.rndB)
      }
      guard encryptedResponse.count == 32 else { throw CardVaultError.malformed }
      var plain = try CardCrypto.cbcDecrypt(key: started.key, iv: CardCrypto.zeroBlock, data: encryptedResponse)
      defer { CardCrypto.wipe(&plain) }
      let bytes = [UInt8](plain)
      guard CardCrypto.constantTimeEqual(Data(bytes[4..<20]), CardCrypto.rotateLeft(started.rndA)) else {
        throw CardVaultError.cardDidNotProve
      }
      let enc = try CardCrypto.cmac(key: started.key, message: Self.sessionVector([0xA5, 0x5A], rndA: started.rndA, rndB: started.rndB))
      let mac = try CardCrypto.cmac(key: started.key, message: Self.sessionVector([0x5A, 0xA5], rndA: started.rndA, rndB: started.rndB))
      session = Session(enc: enc, mac: mac, keyNo: started.keyNo, uid: started.uid)
      return Data(bytes[0..<4])
    }
  }

  // MARK: Secure messaging

  private func open() throws -> Session {
    guard let session else { throw CardVaultError.noSession }
    return session
  }

  func cmac(_ input: Data) throws -> Data {
    try locked { try CardCrypto.cmac(key: try open().mac, message: input) }
  }

  private func encrypt(ivInput: Data, plaintext: Data, session: Session) throws -> Data {
    guard ivInput.count == 16, plaintext.count % 16 == 0, !plaintext.isEmpty else { throw CardVaultError.malformed }
    let iv = try CardCrypto.encryptBlock(key: session.enc, block: ivInput)
    return try CardCrypto.cbcEncrypt(key: session.enc, iv: iv, data: plaintext)
  }

  func encryptPadded(ivInput: Data, padded: Data) throws -> Data {
    try locked { try encrypt(ivInput: ivInput, plaintext: padded, session: try open()) }
  }

  /// The ChangeKey cryptogram: NewKey || KeyVer for the session's own key,
  /// else (NewKey XOR OldKey) || KeyVer || CRC32(NewKey); padded, encrypted.
  func encryptChangeKey(ivInput: Data, keyNo: Int, to: String, from: String, version: Int) throws -> Data {
    try locked {
      let session = try open()
      guard (0...255).contains(version) else { throw CardVaultError.malformed }
      var newKey = try cardKey(uid: session.uid, set: to, keyNo: keyNo)
      defer { CardCrypto.wipe(&newKey) }
      var plain: Data
      if keyNo == session.keyNo {
        plain = CardCrypto.pad(newKey + [UInt8(version)])
      } else {
        var oldKey = try cardKey(uid: session.uid, set: from, keyNo: keyNo)
        defer { CardCrypto.wipe(&oldKey) }
        plain = CardCrypto.pad(CardCrypto.xor(newKey, oldKey) + [UInt8(version)] + CardCrypto.crc32NewKey(newKey))
      }
      defer { CardCrypto.wipe(&plain) }
      return try encrypt(ivInput: ivInput, plaintext: plain, session: session)
    }
  }

  func decrypt(ivInput: Data, ciphertext: Data) throws -> Data {
    try locked {
      let session = try open()
      guard ivInput.count == 16, ciphertext.count % 16 == 0 else { throw CardVaultError.malformed }
      let iv = try CardCrypto.encryptBlock(key: session.enc, block: ivInput)
      return try CardCrypto.cbcDecrypt(key: session.enc, iv: iv, data: ciphertext)
    }
  }

  private func clearSession() {
    if var ended = session {
      CardCrypto.wipe(&ended.enc)
      CardCrypto.wipe(&ended.mac)
    }
    if var started = pending {
      CardCrypto.wipe(&started.key)
      CardCrypto.wipe(&started.rndA)
      CardCrypto.wipe(&started.rndB)
    }
    session = nil
    pending = nil
  }

  func endSession() {
    locked { clearSession() }
  }

  // MARK: The card's keys

  func hasKeys(_ uid: String) throws -> Bool {
    try CardKeychain.contains(uid)
  }

  /// Draws key 0, key 2 and the sealing key from the system random source
  /// and saves them before the card changes.
  func makeKeys(_ uid: String) throws {
    var keys = CardKeys(master: try CardCrypto.random(16), file: try CardCrypto.random(16), seal: try CardCrypto.random(32))
    defer { keys.wipe() }
    try CardKeychain.save(uid, keys: keys)
  }

  func forgetKeys(_ uid: String) throws {
    try CardKeychain.delete(uid)
  }

  // MARK: The Phantom Key

  /// Seals the checked Phantom Key the native core holds under the card's
  /// sealing key (AES-256-GCM, the card's UID authenticated). Returns
  /// nonce || ciphertext || tag: nothing readable without this phone's Keychain.
  func sealPhantomKey(_ uid: String) throws -> Data {
    guard var keys = try CardKeychain.load(uid) else { throw CardVaultError.noKeys }
    defer { keys.wipe() }
    var words = [UInt8](repeating: 0, count: Self.maxKeyBytes)
    defer {
      for i in words.indices { words[i] = 0 }
    }
    let count = words.withUnsafeMutableBufferPointer { buffer in
      ghost_wallet_card_copy_new_key(buffer.baseAddress, UInt(buffer.count))
    }
    guard count > 0 else { throw CardVaultError.noPhantomKey }
    var message = Data(words[0..<Int(count)])
    defer { CardCrypto.wipe(&message) }
    let sealed = try AES.GCM.seal(
      message,
      using: SymmetricKey(data: keys.seal),
      authenticating: Self.sealContext + Data(uid.utf8)
    )
    guard let combined = sealed.combined else { throw CardVaultError.malformed }
    return combined
  }

  /// Opens a sealed Phantom Key read from the card and hands it to the
  /// native core, where Summon and Claim use it.
  func openPhantomKey(_ uid: String, sealed: Data) throws {
    guard var keys = try CardKeychain.load(uid) else { throw CardVaultError.noKeys }
    defer { keys.wipe() }
    let box: AES.GCM.SealedBox
    do {
      box = try AES.GCM.SealedBox(combined: sealed)
    } catch {
      throw CardVaultError.sealedBroken
    }
    var words: Data
    do {
      words = try AES.GCM.open(box, using: SymmetricKey(data: keys.seal), authenticating: Self.sealContext + Data(uid.utf8))
    } catch {
      throw CardVaultError.sealedBroken
    }
    defer { CardCrypto.wipe(&words) }
    let result = words.withUnsafeBytes { bytes in
      ghost_wallet_card_hold_key(bytes.bindMemory(to: UInt8.self).baseAddress, UInt(bytes.count))
    }
    guard result == 0 else { throw CardVaultError.notAPhantomKey }
  }
}
