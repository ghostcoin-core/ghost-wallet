import Foundation
import Security

#if canImport(ghost_wallet_core)
  import ghost_wallet_core

  /// The step records of the kill-recovery prototype, in the Keychain: one
  /// generic password item per payment id, readable only while the phone is
  /// unlocked and only on this device (no iCloud Keychain, not in backups that
  /// restore elsewhere).
  ///
  /// Each item holds the record's stored form from the native core
  /// (`encodeStepRecord`); the native core checks its checksum on every read.
  /// Only these prototype records go here, never account words or keys.
  final class KeychainStepStore: StepStore {
    /// The Keychain service of every record of this store.
    let service: String

    init(service: String = "ghost-wallet.bench.step-records") {
      self.service = service
    }

    private func query(_ id: String? = nil) -> [String: Any] {
      var query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrSynchronizable as String: kCFBooleanFalse as Any,
      ]
      if let id = id {
        query[kSecAttrAccount as String] = id
      }
      return query
    }

    func save(record: StepRecord) throws {
      let data = encodeStepRecord(record: record)
      var add = query(record.id)
      add[kSecValueData as String] = data
      add[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
      var status = SecItemAdd(add as CFDictionary, nil)
      if status == errSecDuplicateItem {
        let update: [String: Any] = [
          kSecValueData as String: data,
          kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]
        status = SecItemUpdate(query(record.id) as CFDictionary, update as CFDictionary)
      }
      guard status == errSecSuccess else {
        throw StepError.Store(reason: "the Keychain did not save the record (\(Self.describe(status)))")
      }
    }

    func load(id: String) throws -> StepRecord? {
      var search = query(id)
      search[kSecReturnData as String] = true
      search[kSecMatchLimit as String] = kSecMatchLimitOne
      var result: CFTypeRef?
      let status = SecItemCopyMatching(search as CFDictionary, &result)
      if status == errSecItemNotFound {
        return nil
      }
      guard status == errSecSuccess else {
        throw StepError.Store(reason: "the Keychain did not read the record (\(Self.describe(status)))")
      }
      guard let data = result as? Data else {
        throw StepError.Unreadable(id: id, reason: "the Keychain item holds no data")
      }
      do {
        return try decodeStepRecord(bytes: data)
      } catch StepError.Unreadable(_, let reason) {
        throw StepError.Unreadable(id: id, reason: reason)
      }
    }

    func list() throws -> [String] {
      var search = query()
      search[kSecReturnAttributes as String] = true
      search[kSecMatchLimit as String] = kSecMatchLimitAll
      var result: CFTypeRef?
      let status = SecItemCopyMatching(search as CFDictionary, &result)
      if status == errSecItemNotFound {
        return []
      }
      guard status == errSecSuccess else {
        throw StepError.Store(reason: "the Keychain did not list the records (\(Self.describe(status)))")
      }
      let items = result as? [[String: Any]] ?? []
      return items.compactMap { $0[kSecAttrAccount as String] as? String }.sorted()
    }

    func remove(id: String) throws {
      let status = SecItemDelete(query(id) as CFDictionary)
      guard status == errSecSuccess || status == errSecItemNotFound else {
        throw StepError.Store(reason: "the Keychain did not remove the record (\(Self.describe(status)))")
      }
    }

    /// Writes raw bytes under an id: only for the tamper check of the
    /// benchmark, to show a damaged record is refused.
    func saveRaw(id: String, bytes: Data) throws {
      try remove(id: id)
      var add = query(id)
      add[kSecValueData as String] = bytes
      add[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
      let status = SecItemAdd(add as CFDictionary, nil)
      guard status == errSecSuccess else {
        throw StepError.Store(reason: "the Keychain did not save the record (\(Self.describe(status)))")
      }
    }

    private static func describe(_ status: OSStatus) -> String {
      let message = SecCopyErrorMessageString(status, nil) as String? ?? "no message"
      return "OSStatus \(status): \(message)"
    }
  }
#endif
