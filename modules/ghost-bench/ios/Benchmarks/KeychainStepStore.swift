import CryptoKit
import Foundation
import Security

#if GHOST_CORE_BINDINGS
  /// The payment records of the kill-recovery benchmark.
  ///
  /// Each record is small (the intent, its identity, the attempts' hashes,
  /// where it landed) and lives in the Keychain: one generic password item per
  /// payment id, readable only while the phone is unlocked and only on this
  /// device (no iCloud Keychain, not in backups that restore elsewhere). The
  /// native core checks its checksum on every read.
  ///
  /// The signed bytes of each attempt are too large for the Keychain (a proof
  /// is over a megabyte), so they are payloads in the app's Application
  /// Support folder: encrypted with AES-GCM under a key kept in the Keychain
  /// (same protection as the records), the payment id and the attempt hash
  /// bound in as associated data, written atomically with
  /// `completeFileProtection` and excluded from backups. A payload is written
  /// before the record lists it, so a kill between the two leaves only bytes
  /// that were never sent; removing a record removes its payloads.
  ///
  /// Only these benchmark records go here, never account words or keys. The
  /// signed bytes are never logged or put in an error.
  final class KeychainStepStore: PaymentStore {
    /// The Keychain service of every record of this store.
    let service: String
    /// The folder holding one folder of payloads per payment.
    let payloadRoot: URL

    init(
      service: String = "ghost-wallet.bench.payment-records",
      payloadRoot: URL = KeychainStepStore.defaultPayloadRoot
    ) {
      self.service = service
      self.payloadRoot = payloadRoot
    }

    static var defaultPayloadRoot: URL {
      let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
      return support.appendingPathComponent("bench-payment-payloads", isDirectory: true)
    }

    /// The account of the payload key's Keychain item, apart from every
    /// payment id (those start with a letter or digit, never a dot).
    private static let payloadKeyAccount = ".payload-key"

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

    // MARK: Records

    func save(record: PaymentRecord) throws {
      try saveItem(id: record.id, data: encodePaymentRecord(record: record), what: "record")
    }

    func load(id: String) throws -> PaymentRecord? {
      guard let data = try loadItem(id: id, what: "record") else { return nil }
      do {
        return try decodePaymentRecord(bytes: data)
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
      return items.compactMap { $0[kSecAttrAccount as String] as? String }
        .filter { $0 != Self.payloadKeyAccount }
        .sorted()
    }

    func remove(id: String) throws {
      let status = SecItemDelete(query(id) as CFDictionary)
      guard status == errSecSuccess || status == errSecItemNotFound else {
        throw StepError.Store(reason: "the Keychain did not remove the record (\(Self.describe(status)))")
      }
      let folder = payloadFolder(id)
      if FileManager.default.fileExists(atPath: folder.path) {
        do {
          try FileManager.default.removeItem(at: folder)
        } catch {
          throw StepError.Store(reason: "the payloads of the record were not removed")
        }
      }
    }

    /// Writes raw bytes under an id: only for the tamper check of the
    /// benchmark, to show a damaged record is refused.
    func saveRaw(id: String, bytes: Data) throws {
      try saveItem(id: id, data: bytes, what: "record")
    }

    // MARK: Payloads

    func savePayload(id: String, transactionHash: Data, signedTransaction: Data) throws {
      let sealed: Data
      do {
        let box = try AES.GCM.seal(
          signedTransaction, using: try payloadKey(), authenticating: Self.boundData(id: id, hash: transactionHash))
        guard let combined = box.combined else {
          throw StepError.Store(reason: "the payload could not be encrypted")
        }
        sealed = combined
      } catch let error as StepError {
        throw error
      } catch {
        throw StepError.Store(reason: "the payload could not be encrypted")
      }
      do {
        try makePayloadFolder(id)
        // Written to a temporary file and renamed into place: whole or not
        // at all, and only readable while the phone is unlocked.
        try sealed.write(to: payloadURL(id, transactionHash), options: [.atomic, .completeFileProtection])
      } catch {
        throw StepError.Store(reason: "the payload was not written (\((error as NSError).code))")
      }
    }

    func loadPayload(id: String, transactionHash: Data) throws -> Data? {
      let url = payloadURL(id, transactionHash)
      guard FileManager.default.fileExists(atPath: url.path) else { return nil }
      let sealed: Data
      do {
        sealed = try Data(contentsOf: url)
      } catch {
        throw StepError.Store(reason: "the payload was not read (\((error as NSError).code))")
      }
      do {
        let box = try AES.GCM.SealedBox(combined: sealed)
        return try AES.GCM.open(
          box, using: try payloadKey(), authenticating: Self.boundData(id: id, hash: transactionHash))
      } catch let error as StepError {
        throw error
      } catch {
        throw StepError.Tampered(id: id, reason: "the payload does not decrypt")
      }
    }

    /// The payment id and the attempt hash: a payload copied to another
    /// payment or attempt does not decrypt.
    private static func boundData(id: String, hash: Data) -> Data {
      var data = Data("ghost-wallet payment payload".utf8)
      let idBytes = Data(id.utf8)
      withUnsafeBytes(of: UInt32(idBytes.count).bigEndian) { data.append(contentsOf: $0) }
      data.append(idBytes)
      data.append(hash)
      return data
    }

    private func payloadFolder(_ id: String) -> URL {
      // Hex of the id: any id is a safe file name.
      payloadRoot.appendingPathComponent(Hex.encode(Data(id.utf8)), isDirectory: true)
    }

    private func payloadURL(_ id: String, _ hash: Data) -> URL {
      payloadFolder(id).appendingPathComponent(Hex.encode(hash) + ".payload")
    }

    private func makePayloadFolder(_ id: String) throws {
      let manager = FileManager.default
      let protection: [FileAttributeKey: Any] = [.protectionKey: FileProtectionType.complete]
      if !manager.fileExists(atPath: payloadRoot.path) {
        try manager.createDirectory(at: payloadRoot, withIntermediateDirectories: true, attributes: protection)
        var root = payloadRoot
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try root.setResourceValues(values)
      }
      let folder = payloadFolder(id)
      if !manager.fileExists(atPath: folder.path) {
        try manager.createDirectory(at: folder, withIntermediateDirectories: true, attributes: protection)
      }
    }

    /// The payload key, made on first use: 256 random bits in the Keychain.
    private func payloadKey() throws -> SymmetricKey {
      if let stored = try loadItem(id: Self.payloadKeyAccount, what: "payload key") {
        guard stored.count == 32 else {
          throw StepError.Tampered(id: Self.payloadKeyAccount, reason: "the payload key is not 256 bits")
        }
        return SymmetricKey(data: stored)
      }
      var bytes = Data(count: 32)
      let status = bytes.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
      guard status == errSecSuccess else {
        throw StepError.Store(reason: "no random bytes for the payload key (\(Self.describe(status)))")
      }
      try addItem(id: Self.payloadKeyAccount, data: bytes, what: "payload key")
      return SymmetricKey(data: bytes)
    }

    // MARK: Keychain items

    private func saveItem(id: String, data: Data, what: String) throws {
      var add = query(id)
      add[kSecValueData as String] = data
      add[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
      var status = SecItemAdd(add as CFDictionary, nil)
      if status == errSecDuplicateItem {
        let update: [String: Any] = [
          kSecValueData as String: data,
          kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]
        status = SecItemUpdate(query(id) as CFDictionary, update as CFDictionary)
      }
      guard status == errSecSuccess else {
        throw StepError.Store(reason: "the Keychain did not save the \(what) (\(Self.describe(status)))")
      }
    }

    /// Adds an item that must not exist yet (the payload key is never
    /// replaced: that would strand every payload).
    private func addItem(id: String, data: Data, what: String) throws {
      var add = query(id)
      add[kSecValueData as String] = data
      add[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
      let status = SecItemAdd(add as CFDictionary, nil)
      guard status == errSecSuccess else {
        throw StepError.Store(reason: "the Keychain did not save the \(what) (\(Self.describe(status)))")
      }
    }

    private func loadItem(id: String, what: String) throws -> Data? {
      var search = query(id)
      search[kSecReturnData as String] = true
      search[kSecMatchLimit as String] = kSecMatchLimitOne
      var result: CFTypeRef?
      let status = SecItemCopyMatching(search as CFDictionary, &result)
      if status == errSecItemNotFound {
        return nil
      }
      guard status == errSecSuccess else {
        throw StepError.Store(reason: "the Keychain did not read the \(what) (\(Self.describe(status)))")
      }
      guard let data = result as? Data else {
        throw StepError.Unreadable(id: id, reason: "the Keychain item holds no data")
      }
      return data
    }

    private static func describe(_ status: OSStatus) -> String {
      let message = SecCopyErrorMessageString(status, nil) as String? ?? "no message"
      return "OSStatus \(status): \(message)"
    }
  }
#endif
