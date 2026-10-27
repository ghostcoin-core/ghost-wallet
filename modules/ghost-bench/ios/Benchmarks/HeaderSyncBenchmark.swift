import Foundation
import UIKit

enum HeaderSyncBenchmarkError: LocalizedError {
  case bindingsMissing
  case noNodeUrl
  case badNodeUrl
  case startNotPinned
  case badConfig(String)
  case node(String)
  case batchUnsupported
  case badHeader(UInt64, String)
  case refused(height: UInt64, reason: String)
  case stalled(UInt64)
  case notLinkedToCheckpoint(UInt64)
  case runStopped(height: UInt64, reason: String)

  var errorDescription: String? {
    switch self {
    case .bindingsMissing:
      return "The Swift bindings of the native core (ghost_wallet_core) are not in this build."
    case .noNodeUrl:
      return "No test node is set: put its JSON-RPC URL in the UserDefaults key "
        + "\(TestChainConfig.nodeUrlKey)."
    case .badNodeUrl:
      return "The test node URL in \(TestChainConfig.nodeUrlKey) is not an http or https URL."
    case .startNotPinned:
      return "No start is pinned in TestChainConfig.swift. The node's block 0 is in the note "
        + "nodeGenesisRlpHex: check it against the test chain's genesis hash and pin it."
    case .badConfig(let reason):
      return "TestChainConfig.swift is wrong: \(reason)."
    case .node(let reason):
      return "The test node did not answer as expected: \(reason)."
    case .batchUnsupported:
      return "The test node refused a JSON-RPC batch. It has no header-range call, and this "
        + "benchmark reads header ranges as batches of eth_getBlockByNumber."
    case .badHeader(let height, let reason):
      return "The node's header at height \(height) could not be read: \(reason)."
    case .refused(let height, let reason):
      return "The header at height \(height) was refused: \(reason)."
    case .stalled(let height):
      return "The node's headers do not extend the checked chain past height \(height)."
    case .notLinkedToCheckpoint(let height):
      return "The node's header at height \(height) does not link to the pinned checkpoint's hash."
    case .runStopped(let height, let reason):
      return "The header run stopped before height \(height): \(reason)."
    }
  }
}

/// Downloads the test chain's headers from a Ghost test node, starting at the
/// start pinned in TestChainConfig.swift (the genesis, or a checkpoint whose
/// next header must link to it), and checks each one on the phone
/// with Ghost's header chain (proof of work with RandomX in its interpreted
/// light mode, and ASERT difficulty), through the native core's HeaderSync.
///
/// Stage `sync` checks every header up to `resumeHeaders` below the node's
/// tip, in one budgeted header run. The benchmark then releases the RandomX
/// caches, as the app does before a proof, and waits for the app to be
/// backgrounded and brought back (send it to the home screen and reopen it).
/// Stage `resume` starts a second run, which rebuilds the chain from the
/// state HeaderSync saved, and fetches and checks the rest from its best
/// height: no header is checked twice. Each run stops on its budget
/// (`runBudget`), at thermal state serious or above and in Low Power Mode;
/// note `headerBudgetOk` says whether both runs finished inside their budget.
///
/// The node has no header-range call (Ghost documents only
/// eth_getBlockByNumber for headers), so a range is one JSON-RPC batch of
/// eth_getBlockByNumber requests, each header re-encoded to its RLP here.
enum HeaderSyncBenchmark {
  static let name = "header-sync"

  static func run(_ context: BenchContext) throws {
    #if GHOST_CORE_BINDINGS
      context.note(
        "headerSource", "eth_getBlockByNumber in JSON-RPC batches; the node has no header-range call")
      context.note("randomx", "interpreted, light caches, no JIT")
      guard
        let text = UserDefaults.standard.string(forKey: TestChainConfig.nodeUrlKey), !text.isEmpty
      else {
        throw HeaderSyncBenchmarkError.noNodeUrl
      }
      guard let url = URL(string: text), url.scheme == "http" || url.scheme == "https" else {
        throw HeaderSyncBenchmarkError.badNodeUrl
      }
      let node = TestNodeClient(url: url)
      let sync = try makeSync(node: node, context: context)
      let startHeight = sync.bestHeight()
      context.note("startHeight", String(startHeight))
      var tally = Tally()

      let syncStart = uptime()
      try context.stage("sync") {
        let tip = try node.blockNumber()
        context.note("nodeTipAtStart", String(tip))
        let target = tip > TestChainConfig.resumeHeaders ? tip - TestChainConfig.resumeHeaders : 0
        let run = sync.startRun(budget: runBudget, conditions: conditions())
        try syncThrough(target, sync: sync, run: run, node: node, context: context, tally: &tally)
      }
      let syncSeconds = uptime() - syncStart
      context.note("syncedHeaders", String(tally.accepted))
      context.note("syncSeconds", String(format: "%.3f", syncSeconds))
      context.note("headersPerSecond", rate(tally.accepted, syncSeconds))
      context.note("checkedHeadersPerSecond", rate(tally.accepted, tally.checkSeconds))
      context.note("syncCpuSeconds", String(format: "%.3f", tally.cpuSeconds))

      // As before a proof: the caches go, and the next run rebuilds the chain
      // from the saved state.
      context.note("cachesReleased", sync.releaseCaches() ? "true" : "false")
      context.note("cacheCountAfterRelease", String(sync.cacheCount()))
      sync.allowCaches()

      let away = waitForBackgroundRoundTrip()
      context.note("backgrounded", away.backgrounded ? "true" : "false")
      context.note("backgroundSeconds", String(format: "%.1f", away.seconds))

      var resumed = Tally()
      let resumeStart = uptime()
      try context.stage("resume") {
        let tip = try node.blockNumber()
        context.note("nodeTipAtResume", String(tip))
        let run = sync.startRun(budget: runBudget, conditions: conditions())
        try syncThrough(tip, sync: sync, run: run, node: node, context: context, tally: &resumed)
      }
      context.note("headerBudgetOk", "true")
      context.note("resumeHeaders", String(resumed.accepted))
      context.note("resumeSeconds", String(format: "%.3f", uptime() - resumeStart))
      context.note("resumeCpuSeconds", String(format: "%.3f", resumed.cpuSeconds))
      context.note("reorgCount", String(tally.reorgs + resumed.reorgs))
      context.note("bestHeight", String(sync.bestHeight()))
      context.note("cacheCount", String(sync.cacheCount()))
      context.note("maxCacheCount", String(max(tally.maxCacheCount, resumed.maxCacheCount)))
    #else
      throw HeaderSyncBenchmarkError.bindingsMissing
    #endif
  }

  struct Tally {
    var accepted: UInt64 = 0
    var checkSeconds: Double = 0
    var cpuSeconds: Double = 0
    var maxCacheCount: UInt64 = 0
    var reorgs = 0
  }

  #if GHOST_CORE_BINDINGS
    /// What one header run may spend: the CPU time of its checks, the
    /// headers and the bytes it looks at.
    static let runBudget = RunBudget(
      cpuSeconds: 1800, maxHeaders: 20_000, maxBytes: 32 * 1024 * 1024)

    /// The phone's thermal state and Low Power Mode, read now.
    static func conditions() -> DeviceConditions {
      let info = ProcessInfo.processInfo
      let thermal: ThermalState
      switch info.thermalState {
      case .nominal: thermal = .nominal
      case .fair: thermal = .fair
      case .serious: thermal = .serious
      case .critical: thermal = .critical
      @unknown default: thermal = .critical
      }
      return DeviceConditions(thermal: thermal, lowPowerMode: info.isLowPowerModeEnabled)
    }

    static func constants() -> HeaderChainConstants {
      HeaderChainConstants(
        blockTime: TestChainConfig.blockTime,
        halfLife: TestChainConfig.halfLife,
        startDifficulty: TestChainConfig.startDifficulty,
        minDifficulty: TestChainConfig.minDifficulty,
        futureDrift: TestChainConfig.futureDrift)
    }

    /// The HeaderSync at the pinned start. With no start pinned, it records
    /// the node's block 0 for the person filling in TestChainConfig.swift and
    /// fails: a start the node chose is never trusted.
    static func makeSync(node: TestNodeClient, context: BenchContext) throws -> HeaderSync {
      switch try TestChainConfig.start {
      case .genesis(let rlpHex):
        if rlpHex.isEmpty {
          if let genesis = try? node.headers(from: 0, through: 0).first {
            context.note("nodeGenesisRlpHex", Hex.encode(genesis))
          }
          throw HeaderSyncBenchmarkError.startNotPinned
        }
        guard let genesis = Hex.decode(rlpHex) else {
          throw HeaderSyncBenchmarkError.badConfig("the genesis header is not hex")
        }
        return try HeaderSync.fromGenesis(genesis: genesis, constants: constants())
      case .checkpoint(let rlpHex, let height, let totalWorkHex, let genesisTimestamp, let keyBlocks):
        guard let header = Hex.decode(rlpHex), !header.isEmpty else {
          throw HeaderSyncBenchmarkError.badConfig("the checkpoint header is not hex")
        }
        guard let totalWork = Hex.decode(totalWorkHex) else {
          throw HeaderSyncBenchmarkError.badConfig("the checkpoint's total work is not hex")
        }
        let pinnedKeys = try keyBlocks.map { block -> PinnedKeyBlock in
          guard let hash = Hex.decode(block.hashHex), hash.count == 32 else {
            throw HeaderSyncBenchmarkError.badConfig("a key block hash is not 32 bytes of hex")
          }
          return PinnedKeyBlock(height: block.height, hash: hash)
        }
        let sync = try HeaderSync.fromCheckpoint(
          header: header, height: height, totalWork: totalWork,
          genesisTimestamp: genesisTimestamp, keyBlocks: pinnedKeys, constants: constants())
        context.note("start", "checkpoint")
        context.note("checkpointHeight", String(height))
        try checkLinksToCheckpoint(sync: sync, height: height, node: node)
        return sync
      }
    }

    /// The node's header after the checkpoint must name the checkpoint as its
    /// parent: otherwise the node is on another chain and the run fails
    /// before checking anything. That header is then fetched again and fully
    /// checked by HeaderSync like every other one.
    static func checkLinksToCheckpoint(sync: HeaderSync, height: UInt64, node: TestNodeClient) throws {
      guard let next = try node.headers(from: height + 1, through: height + 1).first,
        let parent = HeaderRlp.parentHash(next)
      else {
        throw HeaderSyncBenchmarkError.badHeader(height + 1, "it has no parent hash")
      }
      guard parent == sync.bestHash() else {
        throw HeaderSyncBenchmarkError.notLinkedToCheckpoint(height + 1)
      }
    }

    /// Fetches and checks headers from the best height up to `target`, in
    /// batches, through `run`. Fails on the first refused header, naming its
    /// height, and when the run stops (its budget, heat, Low Power Mode),
    /// noting why in `headerRunStop`.
    static func syncThrough(
      _ target: UInt64, sync: HeaderSync, run: HeaderRun, node: TestNodeClient,
      context: BenchContext, tally: inout Tally
    ) throws {
      var next = sync.bestHeight() + 1
      while next <= target {
        let last = min(target, next + UInt64(TestChainConfig.batchSize) - 1)
        let batch = try node.headers(from: next, through: last)
        run.setConditions(conditions: conditions())
        let checkStart = uptime()
        let progress = run.addHeaders(batch: batch, now: UInt64(Date().timeIntervalSince1970))
        tally.checkSeconds += uptime() - checkStart
        tally.cpuSeconds = progress.spent.cpuSeconds
        tally.accepted += progress.accepted
        tally.reorgs += progress.reorgs.count
        let caches = sync.cacheCount()
        tally.maxCacheCount = max(tally.maxCacheCount, caches)
        context.note("bestHeight", String(progress.bestHeight))
        context.note("cacheCount", String(caches))
        if let stopped = progress.stopped {
          let at = next + progress.accepted + progress.alreadyHeld
          context.note("headerRunStop", String(describing: stopped))
          switch stopped {
          case .cpuBudget, .headerBudget, .byteBudget: context.note("headerBudgetOk", "false")
          default: break
          }
          if case .invalidChain = stopped, case .invalid(let reason) = sync.state() {
            throw HeaderSyncBenchmarkError.refused(height: at, reason: reason)
          }
          throw HeaderSyncBenchmarkError.runStopped(height: at, reason: String(describing: stopped))
        }
        guard progress.bestHeight >= last else {
          throw HeaderSyncBenchmarkError.stalled(progress.bestHeight)
        }
        next = progress.bestHeight + 1
      }
    }
  #endif

  /// Waits for the app to go to the background and come back, up to
  /// `backgroundWaitSeconds` for it to leave. Returns whether it did and how
  /// long it was away.
  static func waitForBackgroundRoundTrip() -> (backgrounded: Bool, seconds: Double) {
    let entered = DispatchSemaphore(value: 0)
    let returned = DispatchSemaphore(value: 0)
    let center = NotificationCenter.default
    let enterObserver = center.addObserver(
      forName: UIApplication.didEnterBackgroundNotification, object: nil, queue: nil
    ) { _ in entered.signal() }
    let returnObserver = center.addObserver(
      forName: UIApplication.willEnterForegroundNotification, object: nil, queue: nil
    ) { _ in returned.signal() }
    defer {
      center.removeObserver(enterObserver)
      center.removeObserver(returnObserver)
    }
    guard entered.wait(timeout: .now() + TestChainConfig.backgroundWaitSeconds) == .success else {
      return (false, 0)
    }
    let left = Date()
    returned.wait()
    return (true, Date().timeIntervalSince(left))
  }

  static func uptime() -> Double {
    Double(DispatchTime.now().uptimeNanoseconds) / 1_000_000_000
  }

  static func rate(_ count: UInt64, _ seconds: Double) -> String {
    seconds > 0 ? String(format: "%.1f", Double(count) / seconds) : "0"
  }
}

/// JSON-RPC to the test node with URLSession. Call it off the main thread:
/// each call waits for its answer.
final class TestNodeClient {
  private let url: URL
  private let session: URLSession

  init(url: URL) {
    self.url = url
    let configuration = URLSessionConfiguration.ephemeral
    configuration.timeoutIntervalForRequest = TestChainConfig.requestTimeoutSeconds
    session = URLSession(configuration: configuration)
  }

  /// The node's tip height (eth_blockNumber).
  func blockNumber() throws -> UInt64 {
    let body: [String: Any] = ["jsonrpc": "2.0", "id": 1, "method": "eth_blockNumber", "params": []]
    guard let answer = try post(body) as? [String: Any] else {
      throw HeaderSyncBenchmarkError.node("eth_blockNumber did not return an object")
    }
    let result = try Self.result(of: answer)
    guard let text = result as? String, let height = Hex.quantity(text) else {
      throw HeaderSyncBenchmarkError.node("eth_blockNumber did not return a number")
    }
    return height
  }

  /// The RLP of the headers at heights `from` through `last`, in height
  /// order: one JSON-RPC batch of eth_getBlockByNumber(height, false).
  func headers(from: UInt64, through last: UInt64) throws -> [Data] {
    let heights = Array(from...last)
    let body: [[String: Any]] = heights.enumerated().map { index, height in
      [
        "jsonrpc": "2.0", "id": index, "method": "eth_getBlockByNumber",
        "params": ["0x" + String(height, radix: 16), false],
      ]
    }
    guard let answers = try post(body) as? [Any] else {
      throw HeaderSyncBenchmarkError.batchUnsupported
    }
    // Batch answers may come in any order; match them by id.
    var byId: [Int: [String: Any]] = [:]
    for case let answer as [String: Any] in answers {
      if let id = (answer["id"] as? NSNumber)?.intValue {
        byId[id] = answer
      }
    }
    return try heights.enumerated().map { index, height in
      guard let answer = byId[index] else {
        throw HeaderSyncBenchmarkError.node("no answer for height \(height)")
      }
      guard let header = try Self.result(of: answer) as? [String: Any] else {
        throw HeaderSyncBenchmarkError.node("no header at height \(height)")
      }
      do {
        return try HeaderRlp.encode(header)
      } catch HeaderRlp.Failure.field(let reason) {
        throw HeaderSyncBenchmarkError.badHeader(height, reason)
      }
    }
  }

  private static func result(of answer: [String: Any]) throws -> Any {
    if let error = answer["error"] as? [String: Any] {
      let message = error["message"] as? String ?? "an error"
      throw HeaderSyncBenchmarkError.node(message)
    }
    guard let result = answer["result"] else {
      throw HeaderSyncBenchmarkError.node("an answer has no result")
    }
    return result
  }

  private func post(_ body: Any) throws -> Any {
    var request = URLRequest(url: url)
    request.httpMethod = "POST"
    request.setValue("application/json", forHTTPHeaderField: "Content-Type")
    request.httpBody = try JSONSerialization.data(withJSONObject: body)

    let done = DispatchSemaphore(value: 0)
    var outcome: Result<Data, Error> = .failure(HeaderSyncBenchmarkError.node("no answer"))
    let task = session.dataTask(with: request) { data, response, error in
      if let error = error {
        outcome = .failure(HeaderSyncBenchmarkError.node(error.localizedDescription))
      } else if let http = response as? HTTPURLResponse, !(200..<300).contains(http.statusCode) {
        outcome = .failure(HeaderSyncBenchmarkError.node("HTTP status \(http.statusCode)"))
      } else {
        outcome = .success(data ?? Data())
      }
      done.signal()
    }
    task.resume()
    done.wait()
    let data = try outcome.get()
    do {
      return try JSONSerialization.jsonObject(with: data)
    } catch {
      throw HeaderSyncBenchmarkError.node("the answer is not JSON")
    }
  }
}

/// A header as the node's JSON gives it, re-encoded as the RLP list of the
/// 19 fields of spec 05, section 10, whose Keccak-256 is the block hash. The
/// field list is the one Ghost's web app reads (webapp/src/header.mjs). This
/// is only an encoding: every check is HeaderSync's.
enum HeaderRlp {
  enum Failure: Error {
    case field(String)
  }

  enum Kind {
    /// Exactly `size` bytes.
    case fixed
    /// At most `size` bytes.
    case bytes
    /// An integer below 2^size.
    case int
  }

  static let fields: [(name: String, kind: Kind, size: Int)] = [
    ("parentHash", .fixed, 32),
    ("sha3Uncles", .fixed, 32),
    ("miner", .fixed, 20),
    ("stateRoot", .fixed, 32),
    ("transactionsRoot", .fixed, 32),
    ("receiptsRoot", .fixed, 32),
    ("logsBloom", .fixed, 256),
    ("difficulty", .int, 256),
    ("number", .int, 64),
    ("gasLimit", .int, 64),
    ("gasUsed", .int, 64),
    ("timestamp", .int, 64),
    ("extraData", .bytes, 32),
    ("mixHash", .fixed, 32),
    ("nonce", .fixed, 8),
    ("baseFeePerGas", .int, 256),
    ("coinTreeRoot", .fixed, 32),
    ("dataTreeRoot", .fixed, 32),
    ("dataMarkerRoot", .fixed, 32),
  ]

  static func encode(_ header: [String: Any]) throws -> Data {
    var payload: [UInt8] = []
    for field in fields {
      guard let text = header[field.name] as? String else {
        throw Failure.field("it has no \(field.name)")
      }
      guard var value = Hex.decode(text, quantity: field.kind == .int).map({ [UInt8]($0) }) else {
        throw Failure.field("its \(field.name) is not hex")
      }
      switch field.kind {
      case .fixed:
        guard value.count == field.size else {
          throw Failure.field("its \(field.name) is not \(field.size) bytes")
        }
      case .bytes:
        guard value.count <= field.size else {
          throw Failure.field("its \(field.name) is longer than \(field.size) bytes")
        }
      case .int:
        value = Array(value.drop { $0 == 0 })
        guard value.count * 8 <= field.size else {
          throw Failure.field("its \(field.name) is out of range")
        }
      }
      payload += string(value)
    }
    return Data(lengthPrefix(payload.count, base: 0xc0) + payload)
  }

  /// The parent hash of a header's RLP: its first field, 32 bytes. Only a
  /// reading of the encoding above; the header is not checked here.
  static func parentHash(_ rlp: Data) -> Data? {
    let bytes = [UInt8](rlp)
    guard let first = bytes.first, first >= 0xc0 else { return nil }
    let start = first <= 0xf7 ? 1 : 1 + Int(first - 0xf7)
    guard bytes.count >= start + 33, bytes[start] == 0x80 + 32 else { return nil }
    return Data(bytes[(start + 1)..<(start + 33)])
  }

  private static func string(_ bytes: [UInt8]) -> [UInt8] {
    if bytes.count == 1 && bytes[0] < 0x80 {
      return bytes
    }
    return lengthPrefix(bytes.count, base: 0x80) + bytes
  }

  private static func lengthPrefix(_ length: Int, base: UInt8) -> [UInt8] {
    if length < 56 {
      return [base + UInt8(length)]
    }
    var digits: [UInt8] = []
    var rest = length
    while rest > 0 {
      digits.insert(UInt8(rest & 0xff), at: 0)
      rest >>= 8
    }
    return [base + 55 + UInt8(digits.count)] + digits
  }
}

enum Hex {
  /// Bytes from hex, with or without "0x". A quantity may have an odd number
  /// of digits ("0x0", "0x1a2").
  static func decode(_ text: String, quantity: Bool = false) -> Data? {
    var digits = Substring(text)
    if digits.hasPrefix("0x") || digits.hasPrefix("0X") {
      digits = digits.dropFirst(2)
    }
    var padded = String(digits)
    if padded.count % 2 == 1 {
      guard quantity else { return nil }
      padded = "0" + padded
    }
    var out = Data(capacity: padded.count / 2)
    var index = padded.startIndex
    while index < padded.endIndex {
      let next = padded.index(index, offsetBy: 2)
      guard let byte = UInt8(padded[index..<next], radix: 16) else { return nil }
      out.append(byte)
      index = next
    }
    return out
  }

  /// A JSON-RPC quantity ("0x1a") that fits in 64 bits.
  static func quantity(_ text: String) -> UInt64? {
    guard text.hasPrefix("0x"), text.count > 2 else { return nil }
    return UInt64(text.dropFirst(2), radix: 16)
  }

  static func encode(_ data: Data) -> String {
    data.map { String(format: "%02x", $0) }.joined()
  }
}
