import Foundation

/// One run, as appended to bench-results.json. scripts/format-results.js
/// reads these field names; change both together.
struct BenchRecord: Codable {
  struct Device: Codable {
    let model: String
    let systemName: String
    let systemVersion: String
    let lowPowerMode: Bool
  }

  struct Stage: Codable {
    let name: String
    let seconds: Double
  }

  struct Memory: Codable {
    var peakResidentBytes: UInt64
    var peakFootprintBytes: UInt64
    /// Smallest os_proc_available_memory() reading during the run.
    var minAvailableBytes: UInt64
    var warning: Bool
    /// True when the app ended before the run finished (recorded on the next launch).
    var killed: Bool
  }

  struct Thermal: Codable {
    let start: String
    var end: String
    var worst: String
  }

  struct Battery: Codable {
    let startLevel: Double?
    var endLevel: Double?
    /// startLevel - endLevel, as a fraction of a full charge.
    var drop: Double?
    var state: String
  }

  /// "ok", "failed" or "killed".
  var status: String
  var error: String?
  let benchmark: String
  let startedAt: String
  let device: Device
  var stages: [Stage]
  var totalSeconds: Double
  var memory: Memory
  var thermal: Thermal
  var battery: Battery
  /// Free-form numbers a benchmark wants to keep, for example bytes hashed.
  var notes: [String: String]
}

/// Reads and writes the results file and the marker of the run in progress,
/// both in the app's Documents folder.
enum ResultsStore {
  static let resultsFileName = "bench-results.json"
  static let pendingFileName = "bench-pending.json"

  static var documents: URL {
    FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
  }

  static var resultsURL: URL { documents.appendingPathComponent(resultsFileName) }
  static var pendingURL: URL { documents.appendingPathComponent(pendingFileName) }

  private static let lock = NSLock()

  private static func encoder() -> JSONEncoder {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    return encoder
  }

  /// Adds a record to the end of bench-results.json. A file that is not a
  /// JSON array is kept aside as bench-results.unreadable.json, not overwritten.
  static func append(_ record: BenchRecord) throws {
    lock.lock()
    defer { lock.unlock() }

    var records: [Any] = []
    if let data = try? Data(contentsOf: resultsURL) {
      if let existing = try? JSONSerialization.jsonObject(with: data) as? [Any] {
        records = existing
      } else {
        let aside = documents.appendingPathComponent("bench-results.unreadable.json")
        try? FileManager.default.removeItem(at: aside)
        try FileManager.default.moveItem(at: resultsURL, to: aside)
      }
    }
    records.append(try JSONSerialization.jsonObject(with: encoder().encode(record)))
    let data = try JSONSerialization.data(
      withJSONObject: records, options: [.prettyPrinted, .sortedKeys])
    try data.write(to: resultsURL, options: .atomic)
  }

  static func writePending(_ record: BenchRecord) {
    guard let data = try? encoder().encode(record) else { return }
    try? data.write(to: pendingURL, options: .atomic)
  }

  static func clearPending() {
    try? FileManager.default.removeItem(at: pendingURL)
  }

  static func readPending() -> BenchRecord? {
    guard let data = try? Data(contentsOf: pendingURL) else { return nil }
    return try? JSONDecoder().decode(BenchRecord.self, from: data)
  }
}
