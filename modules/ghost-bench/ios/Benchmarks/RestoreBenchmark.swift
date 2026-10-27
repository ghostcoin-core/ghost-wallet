import Foundation

enum RestoreBenchmarkError: LocalizedError {
  case bindingsMissing
  case noNodeUrl
  case badNodeUrl
  case node(String)
  case badBlock(UInt64, String)
  case completeTooEarly(UInt64)
  case notComplete
  case expectedNotSet(found: Int)
  case accountsMissing(found: Int, expected: Int)

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
    case .badBlock(let height, let reason):
      return "The node's block at height \(height) could not be read: \(reason)."
    case .completeTooEarly(let height):
      return "The scan reported complete before the tip, at height \(height)."
    case .notComplete:
      return "The scan did not report complete after every block up to the tip was fed."
    case .expectedNotSet(let found):
      return "The scan found \(found) accounts, but restoreAccountsExpected in "
        + "TestChainConfig.swift is not set: set it to the accounts used on the test chain."
    case .accountsMissing(let found, let expected):
      return "The scan found \(found) accounts; the test chain has \(expected)."
    }
  }
}

/// A clean-phone restore: from the fixed test words alone, with no stored
/// state, find every account of the test wallet on the test chain and its
/// balance, with the header check on.
///
/// Stage `derive` builds the native RestoreScan from the words, which derives
/// the accounts and their public rescue keys. Stage `sync` checks the test
/// chain's headers from the pinned start in TestChainConfig.swift with
/// HeaderSync, as the header-sync benchmark does, and gives the scan its tip.
/// Stage `scan` downloads every block up to that tip and feeds it to the scan
/// with its header and the addresses it touched (transaction senders and
/// receivers, and the recipients of coin reveals), each with its balance after
/// the block. The scan refuses any header that is not the chain HeaderSync
/// checked, and reports incomplete until the last block is in.
///
/// With the test-only override benchTestChain.restoreBirthday set, the scan
/// starts at that block, the wallet's birthday, and feeds nothing below it
/// (note `scannedFrom`); scripts/sim-test.sh pins the checkpoint start just
/// below it, so the header check covers every scanned block.
///
/// Balances are the node's eth_getBalance answers: Ghost cannot prove an
/// account balance yet, so the scan marks every one unverified (note
/// `balanceNote`). Nothing is kept: the scan lives in memory for the run.
enum RestoreBenchmark {
  static let name = "restore"

  /// The app's fixed test words (modules/ghost-core/test-words.ts): Ghost's
  /// public counting-bytes test seed, test data that guards nothing.
  static let testWords =
    "abandon amount liar amount expire adjust cage candy arch gather drum bullet absurd math era "
    + "live bid rhythm alien crouch range attend journey unaware"

  /// The coin tree account, the address of every commit and reveal log.
  static let coinTreeAccount = "0x67686f7374000000000000000000000000000001"
  /// A reveal log has two topics and 248 data bytes; its recipient is the
  /// 20 bytes at offset 196 (tree index, position, remainder, note).
  static let revealLogBytes = 248
  static let revealRecipientOffset = 196

  static func run(_ context: BenchContext) throws {
    #if GHOST_CORE_BINDINGS
      context.note("headerCheck", "on")
      context.note("storedState", "none")
      guard
        let text = UserDefaults.standard.string(forKey: TestChainConfig.nodeUrlKey), !text.isEmpty
      else {
        throw RestoreBenchmarkError.noNodeUrl
      }
      guard let url = URL(string: text), url.scheme == "http" || url.scheme == "https" else {
        throw RestoreBenchmarkError.badNodeUrl
      }
      let headerNode = TestNodeClient(url: url)
      let node = RestoreNodeClient(url: url)
      let restoreStart = HeaderSyncBenchmark.uptime()

      let sync = try HeaderSyncBenchmark.makeSync(node: headerNode, context: context)
      let firstHeight = sync.bestHeight() + 1
      // The wallet's birthday: the scan feeds no block below it. The header
      // check still covers every block from the pinned start.
      let birthday = TestChainConfig.restoreBirthday
      context.note("restoreBirthday", birthday.map { String($0) } ?? "none")
      let scanFrom = max(firstHeight, birthday ?? 0)

      let scan = try context.stage("derive") {
        try RestoreScan(words: testWords, firstHeight: firstHeight, birthday: birthday)
      }
      context.note("accountsDerivedAtStart", String(scan.accounts().count))

      try context.stage("sync") {
        let tip = try headerNode.blockNumber()
        var tally = HeaderSyncBenchmark.Tally()
        try HeaderSyncBenchmark.syncThrough(
          tip, sync: sync, node: headerNode, context: context, tally: &tally)
        context.note("syncedHeaders", String(tally.accepted))
        context.note("maxCacheCount", String(tally.maxCacheCount))
        try scan.setTip(sync: sync)
      }
      let tip = sync.bestHeight()
      context.note("tip", String(tip))

      var touchedCount = 0
      try context.stage("scan") {
        var next = scanFrom
        while next <= tip {
          let last = min(tip, next + UInt64(TestChainConfig.batchSize) - 1)
          let blocks = try node.blocks(from: next, through: last)
          for block in blocks {
            if case .complete = scan.result() {
              throw RestoreBenchmarkError.completeTooEarly(block.height)
            }
            try scan.feedBlock(height: block.height, header: block.header, touched: block.touched)
            touchedCount += block.touched.count
          }
          next = last + 1
          context.note("scannedThrough", String(last))
        }
      }
      context.note("blocksScanned", String(tip >= scanFrom ? tip - scanFrom + 1 : 0))
      context.note("touchedAddresses", String(touchedCount))
      context.note("restoreSeconds", String(format: "%.3f", HeaderSyncBenchmark.uptime() - restoreStart))

      let expected = TestChainConfig.restoreAccountsExpected
      context.note("accountsExpected", String(expected))
      guard case .complete(let accounts, let note, let scannedFrom) = scan.result() else {
        context.note("scanComplete", "false")
        throw RestoreBenchmarkError.notComplete
      }
      context.note("scanComplete", "true")
      context.note("scannedFrom", String(scannedFrom))
      context.note("balanceNote", note)
      context.note("balancesVerified", accounts.contains { $0.unverified } ? "false" : "true")
      let used = accounts.filter { $0.used }
      context.note("accountsFound", String(used.count))
      context.note("accountsFoundIndexes", used.map { String($0.index) }.joined(separator: ","))
      context.note("accountsDerived", String(accounts.count))
      if expected == 0 {
        throw RestoreBenchmarkError.expectedNotSet(found: used.count)
      }
      if used.count != expected {
        throw RestoreBenchmarkError.accountsMissing(found: used.count, expected: expected)
      }
    #else
      throw RestoreBenchmarkError.bindingsMissing
    #endif
  }
}

#if GHOST_CORE_BINDINGS
  /// One downloaded block: its header's RLP and the addresses it touched,
  /// each with its balance after the block.
  struct RestoreBlock {
    let height: UInt64
    let header: Data
    let touched: [TouchedAddress]
  }

  /// The JSON-RPC calls of the restore scan, as JSON-RPC batches. Call it
  /// off the main thread: each call waits for its answer.
  final class RestoreNodeClient {
    private let url: URL
    private let session: URLSession

    init(url: URL) {
      self.url = url
      let configuration = URLSessionConfiguration.ephemeral
      configuration.timeoutIntervalForRequest = TestChainConfig.requestTimeoutSeconds
      session = URLSession(configuration: configuration)
    }

    /// The blocks at heights `from` through `last`, in height order.
    func blocks(from: UInt64, through last: UInt64) throws -> [RestoreBlock] {
      let heights = Array(from...last)
      let bodies = try batch(heights.map { ("eth_getBlockByNumber", [quantity($0), true]) })

      var headers: [Data] = []
      var addressSets: [[String]] = []
      var receiptCalls: [(String, [Any])] = []
      var receiptBlock: [Int] = []
      for (index, body) in bodies.enumerated() {
        let height = heights[index]
        guard let block = body as? [String: Any] else {
          throw RestoreBenchmarkError.badBlock(height, "no block")
        }
        do {
          headers.append(try HeaderRlp.encode(block))
        } catch HeaderRlp.Failure.field(let reason) {
          throw RestoreBenchmarkError.badBlock(height, reason)
        }
        var addresses: [String] = []
        for case let tx as [String: Any] in block["transactions"] as? [Any] ?? [] {
          for field in ["from", "to"] {
            if let address = tx[field] as? String {
              addresses.append(address.lowercased())
            }
          }
          if let hash = tx["hash"] as? String {
            receiptCalls.append(("eth_getTransactionReceipt", [hash]))
            receiptBlock.append(index)
          }
        }
        addressSets.append(addresses)
      }

      // Coin reveals pay their recipient in a coin tree log, not as a "to".
      if !receiptCalls.isEmpty {
        let receipts = try batch(receiptCalls)
        for (number, receipt) in receipts.enumerated() {
          guard let receipt = receipt as? [String: Any] else { continue }
          for case let log as [String: Any] in receipt["logs"] as? [Any] ?? [] {
            if let recipient = Self.revealRecipient(log) {
              addressSets[receiptBlock[number]].append(recipient)
            }
          }
        }
      }

      var balanceCalls: [(String, [Any])] = []
      var lists: [[String]] = []
      for (index, addresses) in addressSets.enumerated() {
        var seen = Set<String>()
        let unique = addresses.filter { $0 != RestoreBenchmark.coinTreeAccount && seen.insert($0).inserted }
        lists.append(unique)
        balanceCalls += unique.map { ("eth_getBalance", [$0, quantity(heights[index])]) }
      }
      var balances: [Any] = []
      if !balanceCalls.isEmpty {
        balances = try batch(balanceCalls)
      }

      return try heights.enumerated().map { index, height in
        let touched = try lists[index].map { address -> TouchedAddress in
          let answer = balances.removeFirst()
          guard let bytes = Hex.decode(address), bytes.count == 20 else {
            throw RestoreBenchmarkError.badBlock(height, "an address is not 20 bytes of hex")
          }
          guard let text = answer as? String, let balance = Hex.decode(text, quantity: true) else {
            throw RestoreBenchmarkError.badBlock(height, "a balance is not a hex quantity")
          }
          return TouchedAddress(address: bytes, balance: balance)
        }
        return RestoreBlock(height: height, header: headers[index], touched: touched)
      }
    }

    /// The recipient of a coin tree reveal log, as lowercase hex.
    static func revealRecipient(_ log: [String: Any]) -> String? {
      guard (log["address"] as? String)?.lowercased() == RestoreBenchmark.coinTreeAccount,
        (log["topics"] as? [Any])?.count == 2,
        let data = (log["data"] as? String).flatMap({ Hex.decode($0) }),
        data.count == RestoreBenchmark.revealLogBytes
      else { return nil }
      let start = data.startIndex + RestoreBenchmark.revealRecipientOffset
      return "0x" + Hex.encode(data[start..<(start + 20)])
    }

    private func quantity(_ height: UInt64) -> String {
      "0x" + String(height, radix: 16)
    }

    /// One JSON-RPC batch; the results in the order of `calls`.
    private func batch(_ calls: [(String, [Any])]) throws -> [Any] {
      let body: [[String: Any]] = calls.enumerated().map { index, call in
        ["jsonrpc": "2.0", "id": index, "method": call.0, "params": call.1]
      }
      var request = URLRequest(url: url)
      request.httpMethod = "POST"
      request.setValue("application/json", forHTTPHeaderField: "Content-Type")
      request.httpBody = try JSONSerialization.data(withJSONObject: body)

      let done = DispatchSemaphore(value: 0)
      var outcome: Result<Data, Error> = .failure(RestoreBenchmarkError.node("no answer"))
      let task = session.dataTask(with: request) { data, response, error in
        if let error = error {
          outcome = .failure(RestoreBenchmarkError.node(error.localizedDescription))
        } else if let http = response as? HTTPURLResponse, !(200..<300).contains(http.statusCode) {
          outcome = .failure(RestoreBenchmarkError.node("HTTP status \(http.statusCode)"))
        } else {
          outcome = .success(data ?? Data())
        }
        done.signal()
      }
      task.resume()
      done.wait()
      let data = try outcome.get()
      guard let answers = try? JSONSerialization.jsonObject(with: data) as? [Any] else {
        throw RestoreBenchmarkError.node("the node did not answer a JSON-RPC batch")
      }
      // Batch answers may come in any order; match them by id.
      var byId: [Int: [String: Any]] = [:]
      for case let answer as [String: Any] in answers {
        if let id = (answer["id"] as? NSNumber)?.intValue {
          byId[id] = answer
        }
      }
      return try calls.indices.map { index in
        guard let answer = byId[index] else {
          throw RestoreBenchmarkError.node("no answer to \(calls[index].0)")
        }
        if let error = answer["error"] as? [String: Any] {
          throw RestoreBenchmarkError.node(error["message"] as? String ?? "an error")
        }
        guard let result = answer["result"] else {
          throw RestoreBenchmarkError.node("an answer to \(calls[index].0) has no result")
        }
        return result
      }
    }
  }
#endif
