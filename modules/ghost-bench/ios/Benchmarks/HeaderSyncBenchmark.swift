import Foundation

enum HeaderSyncBenchmarkError: LocalizedError {
  case bindingsMissing
  case noNodeUrl
  case badNodeUrl
  case node(String)
  case badHeader(UInt64, String)
  case noSealedTip
  case hashMismatch(UInt64)
  case spotCheckFailed(height: UInt64, reason: String)

  var errorDescription: String? {
    switch self {
    case .bindingsMissing:
      return "The Swift bindings of the native core (ghost_wallet_core) are not in this build."
    case .noNodeUrl:
      return "No test node is set: put its JSON-RPC URL in the UserDefaults key "
        + "\(TestChainConfig.nodeUrlKey)."
    case .badNodeUrl:
      return "The test node URL in \(TestChainConfig.nodeUrlKey) is not an http or https URL."
    case .node(let reason):
      return "The test node did not answer as expected: \(reason)."
    case .badHeader(let height, let reason):
      return "The node's header at height \(height) could not be read: \(reason)."
    case .noSealedTip:
      return "The node's tip is block 0, which carries no seal: mine at least one block."
    case .hashMismatch(let height):
      return "The header at height \(height), as re-encoded here, does not hash to the block "
        + "hash the node reports."
    case .spotCheckFailed(let height, let reason):
      return "The spot check of the header at height \(height) failed: \(reason)."
    }
  }
}

/// A spot check of the node's tip: the proof of work of one header, checked
/// on the phone.
///
/// The phone does not check the chain's headers one after another: one
/// RandomX hash costs seconds there, after minutes of cache setup. It checks
/// one header now and then instead. This benchmark measures that check once:
/// stage `fetch` asks the node for its tip, the tip's header and the hash of
/// the tip's key block (Ghost's seed_height); stage `spot check` hands them
/// to the native core's spotCheckHeader, which builds the RandomX cache of
/// that key block (interpreted, light cache, no JIT), hashes the header once,
/// checks the hash against the header's difficulty and that difficulty
/// against TestChainConfig.spotCheckMinDifficulty, and frees the cache.
///
/// Notes `spotCheckCacheSeconds` and `spotCheckHashSeconds` time the two
/// steps; `peakResidentBytes`, `footprintBytes` and `thermalState` are read
/// right after. The benchmark keeps the button name `header-sync`, and notes
/// `headerBudgetOk` `true` when it finishes, as the feasibility report reads
/// it for this benchmark.
///
/// The node has no header-range call (Ghost documents only
/// eth_getBlockByNumber for headers), so a header is read with
/// eth_getBlockByNumber and re-encoded to its RLP here.
enum HeaderSyncBenchmark {
  static let name = "header-sync"

  /// The node's tip, its header and the hash of the tip's key block.
  struct Tip {
    let height: UInt64
    let hash: Data
    let header: Data
    let keyBlockHeight: UInt64
    let keyBlockHash: Data
  }

  static func run(_ context: BenchContext) throws {
    #if GHOST_CORE_BINDINGS
      context.note("headerCheck", "spot check of the node's tip, one header")
      context.note("headerSource", "eth_getBlockByNumber; the node has no header-range call")
      context.note("randomx", "interpreted, light caches, no JIT")
      let node = try nodeClient()
      let tip = try context.stage("fetch") { try fetchTip(node: node, context: context) }

      let report = try context.stage("spot check") {
        try spotCheckHeader(
          header: tip.header, keyBlockHash: tip.keyBlockHash,
          minDifficulty: minDifficulty())
      }
      noteSpotCheck(report, context: context)
      noteDevice(context: context)
      try requirePassed(report, tip: tip)
      context.note("headerBudgetOk", "true")
    #else
      throw HeaderSyncBenchmarkError.bindingsMissing
    #endif
  }

  /// The test node of TestChainConfig.nodeUrlKey.
  static func nodeClient() throws -> TestNodeClient {
    guard
      let text = UserDefaults.standard.string(forKey: TestChainConfig.nodeUrlKey), !text.isEmpty
    else {
      throw HeaderSyncBenchmarkError.noNodeUrl
    }
    guard let url = URL(string: text), url.scheme == "http" || url.scheme == "https" else {
      throw HeaderSyncBenchmarkError.badNodeUrl
    }
    return TestNodeClient(url: url)
  }

  #if GHOST_CORE_BINDINGS
    /// The node's tip, its header, and the height and hash of its key block,
    /// all as the node gives them: the spot check is what checks them.
    static func fetchTip(node: TestNodeClient, context: BenchContext) throws -> Tip {
      let latest = try node.latestBlock()
      context.note("tip", String(latest.height))
      context.note("tipHash", "0x" + Hex.encode(latest.hash))
      guard latest.height > 0 else {
        throw HeaderSyncBenchmarkError.noSealedTip
      }
      guard let header = try node.headers(from: latest.height, through: latest.height).first else {
        throw HeaderSyncBenchmarkError.badHeader(latest.height, "the node returned no header")
      }
      let keyHeight = spotCheckSeedHeight(height: latest.height)
      let keyHash = try node.blockHash(at: keyHeight)
      context.note("keyBlockHeight", String(keyHeight))
      context.note("keyBlockHash", "0x" + Hex.encode(keyHash))
      return Tip(
        height: latest.height, hash: latest.hash, header: header, keyBlockHeight: keyHeight,
        keyBlockHash: keyHash)
    }

    static func noteSpotCheck(_ report: SpotCheckReport, context: BenchContext) {
      context.note("spotCheckHeight", String(report.height))
      context.note("spotCheckDifficulty", "0x" + Hex.encode(report.difficulty))
      context.note("spotCheckMinDifficulty", String(TestChainConfig.spotCheckMinDifficulty))
      context.note("spotCheckCacheSeconds", String(format: "%.3f", report.cacheSeconds))
      context.note("spotCheckHashSeconds", String(format: "%.3f", report.hashSeconds))
      context.note("spotCheckPassed", report.passed ? "true" : "false")
    }

    /// Fails unless the header is the tip the node named and it passed.
    static func requirePassed(_ report: SpotCheckReport, tip: Tip) throws {
      guard report.height == tip.height else {
        throw HeaderSyncBenchmarkError.badHeader(tip.height, "it carries height \(report.height)")
      }
      guard report.hash == tip.hash else {
        throw HeaderSyncBenchmarkError.hashMismatch(tip.height)
      }
      guard report.passed else {
        throw HeaderSyncBenchmarkError.spotCheckFailed(
          height: tip.height, reason: report.failure ?? "no reason given")
      }
    }

    /// The minimum difficulty, big-endian.
    static func minDifficulty() -> Data {
      var value = TestChainConfig.spotCheckMinDifficulty.bigEndian
      return Data(bytes: &value, count: MemoryLayout<UInt64>.size)
    }
  #endif

  /// The process's peak memory so far and the phone's thermal state, read now.
  static func noteDevice(context: BenchContext) {
    if let memory = Metrics.memory() {
      context.note("peakResidentBytes", String(memory.residentPeakBytes))
      context.note("footprintBytes", String(memory.footprintBytes))
    }
    context.note("thermalState", Metrics.thermalName(Metrics.thermalState()))
  }

  static func uptime() -> Double {
    Double(DispatchTime.now().uptimeNanoseconds) / 1_000_000_000
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

  /// The node's tip as it reports it: the height and block hash of its latest
  /// block (eth_getBlockByNumber("latest")), in one call so the two belong to
  /// the same block. Only the node's word: nothing here checks it.
  func latestBlock() throws -> (height: UInt64, hash: Data) {
    let block = try blockObject("latest", name: "latest block")
    guard let numberText = block["number"] as? String, let height = Hex.quantity(numberText) else {
      throw HeaderSyncBenchmarkError.node("the latest block has no number")
    }
    return (height, try Self.hash(of: block, name: "latest block"))
  }

  /// The hash the node reports for its block at `height`. Only the node's
  /// word: nothing here checks it.
  func blockHash(at height: UInt64) throws -> Data {
    let name = "block at height \(height)"
    return try Self.hash(of: try blockObject("0x" + String(height, radix: 16), name: name), name: name)
  }

  /// One eth_getBlockByNumber(tag, false) answer.
  private func blockObject(_ tag: String, name: String) throws -> [String: Any] {
    let body: [String: Any] = [
      "jsonrpc": "2.0", "id": 1, "method": "eth_getBlockByNumber", "params": [tag, false],
    ]
    guard let answer = try post(body) as? [String: Any] else {
      throw HeaderSyncBenchmarkError.node("eth_getBlockByNumber did not return an object")
    }
    guard let block = try Self.result(of: answer) as? [String: Any] else {
      throw HeaderSyncBenchmarkError.node("the node has no \(name)")
    }
    return block
  }

  private static func hash(of block: [String: Any], name: String) throws -> Data {
    guard let hashText = block["hash"] as? String, let hash = Hex.decode(hashText), hash.count == 32
    else {
      throw HeaderSyncBenchmarkError.node("the \(name) has no 32-byte hash")
    }
    return hash
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
      throw HeaderSyncBenchmarkError.node("the node refused a JSON-RPC batch")
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
/// is only an encoding: every check is the native core's.
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
