// Each card's keys in the iOS Keychain, on this phone only.
//
// One generic password item per card: service `com.ghostcoin.wallet.card`,
// account the card's UID (hex), holding key 0, key 2 and the sealing key (16,
// 16 and 32 bytes). `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` and never
// synchronised, so the keys leave no backup that restores on another phone.
import Foundation
import Security

struct CardKeys {
  var master: Data
  var file: Data
  var seal: Data

  static let byteCount = 16 + 16 + 32

  init(master: Data, file: Data, seal: Data) {
    self.master = master
    self.file = file
    self.seal = seal
  }

  init?(stored: Data) {
    guard stored.count == CardKeys.byteCount else { return nil }
    let bytes = [UInt8](stored)
    master = Data(bytes[0..<16])
    file = Data(bytes[16..<32])
    seal = Data(bytes[32..<64])
  }

  var stored: Data { master + file + seal }

  mutating func wipe() {
    CardCrypto.wipe(&master)
    CardCrypto.wipe(&file)
    CardCrypto.wipe(&seal)
  }
}

enum CardKeychainError: Error {
  case status(OSStatus)
  case malformed
}

enum CardKeychain {
  private static let service = "com.ghostcoin.wallet.card"

  private static func query(_ uid: String) -> [String: Any] {
    [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: uid,
      kSecAttrSynchronizable as String: kCFBooleanFalse as Any,
    ]
  }

  static func contains(_ uid: String) throws -> Bool {
    var query = query(uid)
    query[kSecMatchLimit as String] = kSecMatchLimitOne
    let status = SecItemCopyMatching(query as CFDictionary, nil)
    switch status {
    case errSecSuccess: return true
    case errSecItemNotFound: return false
    default: throw CardKeychainError.status(status)
    }
  }

  static func load(_ uid: String) throws -> CardKeys? {
    var query = query(uid)
    query[kSecReturnData as String] = kCFBooleanTrue
    query[kSecMatchLimit as String] = kSecMatchLimitOne
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    switch status {
    case errSecSuccess:
      guard let data = result as? Data, let keys = CardKeys(stored: data) else { throw CardKeychainError.malformed }
      return keys
    case errSecItemNotFound:
      return nil
    default:
      throw CardKeychainError.status(status)
    }
  }

  /// Saves new keys for `uid`; a card's keys are never overwritten.
  static func save(_ uid: String, keys: CardKeys) throws {
    var attributes = query(uid)
    attributes[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    attributes[kSecValueData as String] = keys.stored
    let status = SecItemAdd(attributes as CFDictionary, nil)
    guard status == errSecSuccess else { throw CardKeychainError.status(status) }
  }

  static func delete(_ uid: String) throws {
    let status = SecItemDelete(query(uid) as CFDictionary)
    guard status == errSecSuccess || status == errSecItemNotFound else { throw CardKeychainError.status(status) }
  }
}
