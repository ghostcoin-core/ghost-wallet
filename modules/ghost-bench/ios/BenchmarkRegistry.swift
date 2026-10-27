import Foundation

/// A benchmark is a native function that does its work in named stages. The
/// harness times each stage and watches memory, heat and battery around it.
typealias BenchmarkFunction = (BenchContext) throws -> Void

/// Every benchmark the bench screen can run, by name. To add one, write its
/// function under Benchmarks/ and add one entry here.
enum BenchmarkRegistry {
  static let benchmarks: [String: BenchmarkFunction] = [
    DummyBenchmark.name: DummyBenchmark.run,
    SummonBenchmark.name: SummonBenchmark.run,
    HeaderSyncBenchmark.name: HeaderSyncBenchmark.run,
    RestoreBenchmark.name: RestoreBenchmark.run,
  ]

  static var names: [String] { benchmarks.keys.sorted() }
}

/// What a running benchmark reports to the harness.
final class BenchContext {
  private let lock = NSLock()
  private var stages: [BenchRecord.Stage] = []
  private var notes: [String: String] = [:]

  /// Runs `body` as the stage `name` and records its wall time. A stage that
  /// throws is still recorded, up to the point it failed.
  func stage<T>(_ name: String, _ body: () throws -> T) rethrows -> T {
    let start = DispatchTime.now().uptimeNanoseconds
    defer {
      let seconds = Double(DispatchTime.now().uptimeNanoseconds - start) / 1_000_000_000
      lock.lock()
      stages.append(BenchRecord.Stage(name: name, seconds: seconds))
      lock.unlock()
    }
    return try body()
  }

  /// Keeps a number or short label with the run's record. Never pass secrets.
  func note(_ key: String, _ value: String) {
    lock.lock()
    notes[key] = value
    lock.unlock()
  }

  var recordedStages: [BenchRecord.Stage] {
    lock.lock()
    defer { lock.unlock() }
    return stages
  }

  var recordedNotes: [String: String] {
    lock.lock()
    defer { lock.unlock() }
    return notes
  }
}
