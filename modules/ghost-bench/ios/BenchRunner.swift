import Foundation

enum BenchRunnerError: LocalizedError {
  case unknownBenchmark(String)
  case busy

  var errorDescription: String? {
    switch self {
    case .unknownBenchmark(let name): return "No benchmark is named \(name)."
    case .busy: return "A benchmark is already running."
    }
  }
}

/// Runs one benchmark at a time and writes its record to bench-results.json.
enum BenchRunner {
  private static let lock = NSLock()
  private static var running = false
  private static var writePartial: (() -> Void)?

  /// Writes the running benchmark's marker now, with its notes so far. A
  /// benchmark that is about to end the process on purpose calls this, so
  /// the record of the killed run kept on the next launch has its notes.
  static func flushPending() {
    lock.lock()
    let write = writePartial
    lock.unlock()
    write?()
  }

  /// Runs the named benchmark and returns the record it appended. A benchmark
  /// that throws still produces a record, with status "failed".
  static func run(_ name: String) throws -> BenchRecord {
    guard let benchmark = BenchmarkRegistry.benchmarks[name] else {
      throw BenchRunnerError.unknownBenchmark(name)
    }
    lock.lock()
    if running {
      lock.unlock()
      throw BenchRunnerError.busy
    }
    running = true
    lock.unlock()
    defer {
      lock.lock()
      running = false
      lock.unlock()
    }

    let startBattery = Metrics.battery()
    let startThermal = Metrics.thermalName(Metrics.thermalState())
    var record = BenchRecord(
      status: "running",
      error: nil,
      benchmark: name,
      startedAt: ISO8601DateFormatter().string(from: Date()),
      device: BenchRecord.Device(
        model: Metrics.deviceModel(),
        systemName: "iOS",
        systemVersion: Metrics.systemVersion(),
        lowPowerMode: Metrics.isLowPowerModeEnabled()),
      stages: [],
      totalSeconds: 0,
      memory: BenchRecord.Memory(
        peakResidentBytes: 0, peakFootprintBytes: 0, minAvailableBytes: 0,
        warning: false, killed: false),
      thermal: BenchRecord.Thermal(start: startThermal, end: startThermal, worst: startThermal),
      battery: BenchRecord.Battery(
        startLevel: startBattery.level, endLevel: nil, drop: nil, state: startBattery.state),
      notes: [:])

    let context = BenchContext()
    let monitor = RunMonitor()
    let start = DispatchTime.now().uptimeNanoseconds
    func elapsed() -> Double {
      Double(DispatchTime.now().uptimeNanoseconds - start) / 1_000_000_000
    }

    // If the OS kills the app mid-run, this marker is what the next launch
    // records. It is refreshed about once a second with the peaks so far.
    let base = record
    ResultsStore.writePending(base)
    monitor.start { monitor in
      var partial = base
      BenchRunner.fill(&partial, from: monitor, context: context, seconds: elapsed())
      ResultsStore.writePending(partial)
    }
    lock.lock()
    writePartial = {
      var partial = base
      monitor.snapshot { BenchRunner.fill(&partial, from: $0, context: context, seconds: elapsed()) }
      ResultsStore.writePending(partial)
    }
    lock.unlock()
    defer {
      lock.lock()
      writePartial = nil
      lock.unlock()
    }

    do {
      try benchmark(context)
      record.status = "ok"
    } catch {
      record.status = "failed"
      record.error = error.localizedDescription
    }
    let seconds = elapsed()
    monitor.stop()

    monitor.snapshot { fill(&record, from: $0, context: context, seconds: seconds) }
    let endBattery = Metrics.battery()
    record.thermal.end = Metrics.thermalName(Metrics.thermalState())
    record.battery.endLevel = endBattery.level
    record.battery.state = endBattery.state
    if let startLevel = startBattery.level, let endLevel = endBattery.level {
      record.battery.drop = startLevel - endLevel
    }

    try ResultsStore.append(record)
    ResultsStore.clearPending()
    return record
  }

  /// Called when the module loads: a marker left by a run that never finished
  /// means the app was killed (or closed) mid-run. Record that run as killed.
  static func recordUnfinishedRun() {
    guard var record = ResultsStore.readPending() else {
      ResultsStore.clearPending()
      return
    }
    record.status = "killed"
    record.memory.killed = true
    if (try? ResultsStore.append(record)) != nil {
      ResultsStore.clearPending()
    }
  }

  private static func fill(
    _ record: inout BenchRecord, from monitor: RunMonitor, context: BenchContext, seconds: Double
  ) {
    record.stages = context.recordedStages
    record.notes = context.recordedNotes
    record.totalSeconds = seconds
    record.memory.peakResidentBytes = monitor.peakResidentBytes
    record.memory.peakFootprintBytes = monitor.peakFootprintBytes
    record.memory.minAvailableBytes =
      monitor.minAvailableBytes == .max ? 0 : monitor.minAvailableBytes
    record.memory.warning = monitor.memoryWarning
    let worst = Metrics.thermalName(monitor.worstThermal)
    record.thermal.worst = worst
    record.thermal.end = Metrics.thermalName(Metrics.thermalState())
  }
}
