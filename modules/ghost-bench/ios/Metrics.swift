import Darwin
import Foundation
import UIKit
import os

/// Point-in-time readings of the things a run is judged on: resident memory
/// (task_info), the memory the OS still lets the app take
/// (os_proc_available_memory), the thermal state (ProcessInfo.thermalState),
/// the battery, and which phone and iOS version produced the numbers.
enum Metrics {
  struct Memory {
    /// Pages of this process currently in RAM.
    let residentBytes: UInt64
    /// Highest resident size the kernel has seen for this process so far.
    let residentPeakBytes: UInt64
    /// The footprint jetsam counts against the app's memory limit.
    let footprintBytes: UInt64
  }

  /// Resident size, its kernel-tracked peak and the physical footprint, read
  /// with task_info(TASK_VM_INFO). Nil if the call fails.
  static func memory() -> Memory? {
    var info = task_vm_info_data_t()
    var count = mach_msg_type_number_t(
      MemoryLayout<task_vm_info_data_t>.size / MemoryLayout<natural_t>.size)
    let result = withUnsafeMutablePointer(to: &info) { pointer in
      pointer.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
        task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), $0, &count)
      }
    }
    guard result == KERN_SUCCESS else { return nil }
    return Memory(
      residentBytes: UInt64(info.resident_size),
      residentPeakBytes: UInt64(info.resident_size_peak),
      footprintBytes: UInt64(info.phys_footprint))
  }

  /// Bytes the app can still allocate before it reaches its memory limit.
  static func availableMemoryBytes() -> UInt64 {
    UInt64(os_proc_available_memory())
  }

  static func thermalState() -> ProcessInfo.ThermalState {
    ProcessInfo.processInfo.thermalState
  }

  static func thermalName(_ state: ProcessInfo.ThermalState) -> String {
    switch state {
    case .nominal: return "nominal"
    case .fair: return "fair"
    case .serious: return "serious"
    case .critical: return "critical"
    @unknown default: return "unknown"
    }
  }

  static func isLowPowerModeEnabled() -> Bool {
    ProcessInfo.processInfo.isLowPowerModeEnabled
  }

  struct Battery {
    /// 0...1, or nil where iOS does not report it (the simulator).
    let level: Double?
    let state: String
  }

  static func battery() -> Battery {
    onMain {
      let device = UIDevice.current
      device.isBatteryMonitoringEnabled = true
      let level = device.batteryLevel
      let state: String
      switch device.batteryState {
      case .unplugged: state = "unplugged"
      case .charging: state = "charging"
      case .full: state = "full"
      case .unknown: state = "unknown"
      @unknown default: state = "unknown"
      }
      return Battery(level: level < 0 ? nil : Double(level), state: state)
    }
  }

  /// Hardware identifier, for example "iPhone16,1".
  static func deviceModel() -> String {
    var system = utsname()
    uname(&system)
    return withUnsafeBytes(of: &system.machine) { raw in
      String(decoding: raw.prefix { $0 != 0 }, as: UTF8.self)
    }
  }

  static func systemVersion() -> String {
    let version = ProcessInfo.processInfo.operatingSystemVersion
    return "\(version.majorVersion).\(version.minorVersion).\(version.patchVersion)"
  }

  static func onMain<T>(_ body: () -> T) -> T {
    if Thread.isMainThread {
      return body()
    }
    return DispatchQueue.main.sync(execute: body)
  }
}

/// Watches one run: samples memory and the thermal state on a timer, and
/// notes any memory warning the OS sends while the run is going.
final class RunMonitor {
  private static let sampleInterval = DispatchTimeInterval.milliseconds(100)

  private let queue = DispatchQueue(label: "ghost-bench.monitor", qos: .userInitiated)
  private var timer: DispatchSourceTimer?
  private var pressureSource: DispatchSourceMemoryPressure?
  private var warningObserver: NSObjectProtocol?
  private var onTick: ((RunMonitor) -> Void)?
  private var ticks = 0

  private(set) var peakResidentBytes: UInt64 = 0
  private(set) var peakFootprintBytes: UInt64 = 0
  private(set) var minAvailableBytes: UInt64 = .max
  private(set) var memoryWarning = false
  private(set) var worstThermal: ProcessInfo.ThermalState = .nominal

  /// Starts sampling. `everySecond` runs on the monitor queue about once a
  /// second and gets the monitor itself: read its values directly there, not
  /// through `snapshot`, which would wait on the same queue.
  func start(everySecond: @escaping (RunMonitor) -> Void) {
    worstThermal = Metrics.thermalState()
    onTick = everySecond
    sample()

    warningObserver = NotificationCenter.default.addObserver(
      forName: UIApplication.didReceiveMemoryWarningNotification, object: nil, queue: nil
    ) { [weak self] _ in
      self?.queue.async { self?.memoryWarning = true }
    }

    let pressure = DispatchSource.makeMemoryPressureSource(
      eventMask: [.warning, .critical], queue: queue)
    pressure.setEventHandler { [weak self] in self?.memoryWarning = true }
    pressure.resume()
    pressureSource = pressure

    let timer = DispatchSource.makeTimerSource(queue: queue)
    timer.schedule(deadline: .now() + Self.sampleInterval, repeating: Self.sampleInterval)
    timer.setEventHandler { [weak self] in self?.tick() }
    timer.resume()
    self.timer = timer
  }

  /// Stops sampling after one last reading.
  func stop() {
    queue.sync {
      timer?.cancel()
      timer = nil
      pressureSource?.cancel()
      pressureSource = nil
      onTick = nil
      sample()
    }
    if let observer = warningObserver {
      NotificationCenter.default.removeObserver(observer)
      warningObserver = nil
    }
  }

  /// Reads the current peaks safely from any thread.
  func snapshot<T>(_ body: (RunMonitor) -> T) -> T {
    queue.sync { body(self) }
  }

  private func tick() {
    sample()
    ticks += 1
    if ticks % 10 == 0 {
      onTick?(self)
    }
  }

  private func sample() {
    if let memory = Metrics.memory() {
      peakResidentBytes = max(peakResidentBytes, memory.residentBytes, memory.residentPeakBytes)
      peakFootprintBytes = max(peakFootprintBytes, memory.footprintBytes)
    }
    minAvailableBytes = min(minAvailableBytes, Metrics.availableMemoryBytes())
    let thermal = Metrics.thermalState()
    if thermal.rawValue > worstThermal.rawValue {
      worstThermal = thermal
    }
  }
}
