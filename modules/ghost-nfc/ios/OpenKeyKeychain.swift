// The phone key of a Sealed card's Open, kept in the iOS Keychain until the
// Claim of the opened card settles (docs/sealed-card.md, "The app").
//
// The native core makes the ML-KEM-768 key pair (core/src/seal_open.rs). Its
// 64-byte seed is copied here only to survive an app restart: an Open cut off
// can then be asked again with the same phone key, and the Seal releases the
// card's key only to the phone key bound when the Open started. One generic
// password item, service `com.ghostcoin.wallet.seal-open`,
// `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` and never synchronised, so
// it leaves no backup that restores on another phone. JavaScript never sees
// the seed; nothing here logs it.
import ExpoModulesCore
import Foundation
import Security

final class OpenKeyMissingException: Exception {
  override var reason: String { "No Open is under way on this iPhone." }
}

final class OpenKeyKeychainException: Exception {
  override var reason: String { "The Keychain could not keep the Open's phone key." }
}

enum OpenKeyKeychain {
  private static let service = "com.ghostcoin.wallet.seal-open"
  private static let account = "phone-key"
  private static let seedBytes = 64

  private static func query() -> [String: Any] {
    [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: account,
      kSecAttrSynchronizable as String: kCFBooleanFalse as Any,
    ]
  }

  /// Copies the core's phone key seed into the Keychain, replacing one kept before.
  static func keep() throws {
    var seed = [UInt8](repeating: 0, count: seedBytes)
    defer {
      for i in seed.indices { seed[i] = 0 }
    }
    let copied = seed.withUnsafeMutableBufferPointer { buffer in
      ghost_wallet_seal_open_copy_seed(buffer.baseAddress, UInt(buffer.count))
    }
    guard copied == seedBytes else { throw OpenKeyMissingException() }
    var data = Data(seed)
    defer { CardCrypto.wipe(&data) }
    SecItemDelete(query() as CFDictionary)
    var attributes = query()
    attributes[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    attributes[kSecValueData as String] = data
    guard SecItemAdd(attributes as CFDictionary, nil) == errSecSuccess else { throw OpenKeyKeychainException() }
  }

  /// Gives a kept seed back to the core. False when none is kept.
  static func restore() throws -> Bool {
    var lookup = query()
    lookup[kSecReturnData as String] = kCFBooleanTrue
    lookup[kSecMatchLimit as String] = kSecMatchLimitOne
    var result: CFTypeRef?
    let status = SecItemCopyMatching(lookup as CFDictionary, &result)
    if status == errSecItemNotFound {
      return false
    }
    guard status == errSecSuccess, var data = result as? Data else { throw OpenKeyKeychainException() }
    defer { CardCrypto.wipe(&data) }
    guard data.count == seedBytes else { throw OpenKeyKeychainException() }
    let restored = data.withUnsafeBytes { bytes in
      ghost_wallet_seal_open_restore_seed(bytes.bindMemory(to: UInt8.self).baseAddress, UInt(bytes.count))
    }
    guard restored == 0 else { throw OpenKeyKeychainException() }
    return true
  }

  /// Deletes the kept seed.
  static func forget() {
    SecItemDelete(query() as CFDictionary)
  }
}
