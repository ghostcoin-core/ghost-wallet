// The Phantom Key of an opened Ghost card, kept in the iOS Keychain while the
// card is given a new balance (docs/bearer-card-spec.md, "A card as a vault").
//
// Adding to or taking from a card opens it, clears it and makes it a new key
// for the new total, all in one hold. The opened coin is then Summoned into
// the wallet, which needs its key. The card no longer has it, so a copy is
// kept here, before the card is cleared, until that Summon settles: an app
// killed or a phone switched off in between still takes the coin home. One
// generic password item per opened coin (service
// `com.ghostcoin.wallet.card-key`, account: the coin's public marker),
// `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` and never synchronised, so it
// leaves no backup that restores on another phone. JavaScript never sees the
// key; nothing here logs it.
import ExpoModulesCore
import Foundation
import Security

final class CardKeyMissingException: Exception {
  override var reason: String { "No opened card's key is held on this iPhone." }
}

final class CardKeyKeychainException: Exception {
  override var reason: String { "The Keychain could not keep the opened card's key." }
}

enum CardKeyKeychain {
  private static let service = "com.ghostcoin.wallet.card-key"
  /// Room for a Phantom Key's 24 words.
  private static let capacity = 512

  private static func query(_ tag: String) -> [String: Any] {
    [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: tag,
      kSecAttrSynchronizable as String: kCFBooleanFalse as Any,
    ]
  }

  private static func validTag(_ tag: String) -> Bool {
    tag.count == 64 && tag.allSatisfy { $0.isHexDigit }
  }

  /// Copies the card key the core holds into the Keychain under `tag`,
  /// replacing one kept before under it, and reads it back.
  static func keep(tag: String) throws {
    guard validTag(tag) else { throw CardKeyKeychainException() }
    var words = [UInt8](repeating: 0, count: capacity)
    defer {
      for i in words.indices { words[i] = 0 }
    }
    let copied = words.withUnsafeMutableBufferPointer { buffer in
      ghost_wallet_card_copy_held_key(buffer.baseAddress, UInt(buffer.count))
    }
    guard copied > 0 else { throw CardKeyMissingException() }
    var data = Data(words[0..<Int(copied)])
    defer { CardCrypto.wipe(&data) }
    SecItemDelete(query(tag) as CFDictionary)
    var attributes = query(tag)
    attributes[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    attributes[kSecValueData as String] = data
    guard SecItemAdd(attributes as CFDictionary, nil) == errSecSuccess else { throw CardKeyKeychainException() }
    // Read back: the card is cleared only once the copy is certainly here.
    guard var back = try read(tag) else { throw CardKeyKeychainException() }
    defer { CardCrypto.wipe(&back) }
    guard back == data else { throw CardKeyKeychainException() }
  }

  private static func read(_ tag: String) throws -> Data? {
    var lookup = query(tag)
    lookup[kSecReturnData as String] = kCFBooleanTrue
    lookup[kSecMatchLimit as String] = kSecMatchLimitOne
    var result: CFTypeRef?
    let status = SecItemCopyMatching(lookup as CFDictionary, &result)
    if status == errSecItemNotFound {
      return nil
    }
    guard status == errSecSuccess, let data = result as? Data else { throw CardKeyKeychainException() }
    return data
  }

  /// Gives the key kept under `tag` back to the core as its card key. False
  /// when none is kept.
  static func restore(tag: String) throws -> Bool {
    guard validTag(tag) else { throw CardKeyKeychainException() }
    guard var data = try read(tag) else { return false }
    defer { CardCrypto.wipe(&data) }
    let held = data.withUnsafeBytes { bytes in
      ghost_wallet_card_hold_key(bytes.bindMemory(to: UInt8.self).baseAddress, UInt(bytes.count))
    }
    guard held == 0 else { throw CardKeyKeychainException() }
    return true
  }

  /// Whether a key is kept under `tag`.
  static func has(tag: String) -> Bool {
    guard validTag(tag) else { return false }
    var lookup = query(tag)
    lookup[kSecMatchLimit as String] = kSecMatchLimitOne
    return SecItemCopyMatching(lookup as CFDictionary, nil) == errSecSuccess
  }

  /// Deletes the key kept under `tag`.
  static func forget(tag: String) {
    guard validTag(tag) else { return }
    SecItemDelete(query(tag) as CFDictionary)
  }
}
