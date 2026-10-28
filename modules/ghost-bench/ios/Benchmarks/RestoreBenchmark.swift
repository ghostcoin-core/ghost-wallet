import Foundation

enum RestoreBenchmarkError: LocalizedError {
  case bindingsMissing
  case noNodeUrl
  case badNodeUrl
  case node(String)
  case notComplete
  case expectedNotSet(found: Int)
  case accountsMissing(found: Int, expected: Int)
  case noBalance
  case firstBalanceSlow(seconds: Double, limit: Double)

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
    case .notComplete:
      return "The restore did not reach the gap of unused accounts."
    case .expectedNotSet(let found):
      return "The restore found \(found) accounts, but restoreAccountsExpected in "
        + "TestChainConfig.swift is not set: set it to the accounts used on the test chain."
    case .accountsMissing(let found, let expected):
      return "The restore found \(found) accounts; the test chain has \(expected)."
    case .noBalance:
      return "The restore reported no balance."
    case .firstBalanceSlow(let seconds, let limit):
      return "The first balance took "
        + String(format: "%.2f", seconds) + " s; the limit is " + String(format: "%.0f", limit) + " s."
    }
  }
}

/// A clean-phone restore: from the fixed test words alone, with no stored
/// state, find every account of the test wallet on the test chain and its
/// balance. The result shows as soon as the balances are in: no header is
/// checked and nothing else is waited for (the proof of work is measured on
/// its own, by the header-sync benchmark's spot check).
///
/// The restore takes the node's current tip, a height and a block hash, and
/// builds the native RestoreLookup from the words and that tip. It then asks
/// the node, account after account, for the account's balance and nonce at
/// the tip's block hash (eth_getBalance and eth_getTransactionCount with that
/// hash), until 20 unused accounts follow the last used one. Each balance is
/// reported as soon as it arrives. Stage `first balance` runs from the start
/// to the first one (note `timeToFirstBalanceSeconds`, at most
/// `firstBalanceLimitSeconds`), and stage `lookup`, which holds it, to the
/// last. No block, receipt or transaction is downloaded: the current state
/// already holds plain transfers, contract payments and mining rewards alike.
/// The restore does not start at any height, and finds accounts funded long
/// ago.
///
/// Balances and nonces are the node's answers: Ghost cannot prove an account
/// state yet, so the restore marks every one unverified (note
/// `balanceNote`). Nothing is kept: the restore lives in memory for the run.
enum RestoreBenchmark {
  static let name = "restore"

  /// The app's fixed test words (modules/ghost-core/test-words.ts): Ghost's
  /// public counting-bytes test seed, test data that guards nothing.
  static let testWords =
    "abandon amount liar amount expire adjust cage candy arch gather drum bullet absurd math era "
    + "live bid rhythm alien crouch range attend journey unaware"

  /// The most the first balance may take, from the start of the run.
  static let firstBalanceLimitSeconds: Double = 10

  static func run(_ context: BenchContext) throws {
    #if GHOST_CORE_BINDINGS
      context.note("headerCheck", "none")
      context.note("storedState", "none")
      context.note("lookup", "current state at the node's tip")
      guard
        let text = UserDefaults.standard.string(forKey: TestChainConfig.nodeUrlKey), !text.isEmpty
      else {
        throw RestoreBenchmarkError.noNodeUrl
      }
      guard let url = URL(string: text), url.scheme == "http" || url.scheme == "https" else {
        throw RestoreBenchmarkError.badNodeUrl
      }
      let node = TestNodeClient(url: url)
      let restoreStart = HeaderSyncBenchmark.uptime()

      var timeToFirstBalanceSeconds: Double?
      var lookedUp = 0
      let restore = try context.stage("lookup") { () -> RestoreLookup in
        let (lookup, first) = try context.stage("first balance") {
          () -> (RestoreLookup, RestoredAccount?) in
          // The node's tip, taken at once: no header is checked.
          let tip = try node.latestBlock()
          context.note("tip", String(tip.height))
          context.note("tipHash", "0x" + Hex.encode(tip.hash))
          let lookup = try RestoreLookup(
            words: testWords, lookup: NodeAccountLookup(url: url), tipHeight: tip.height,
            tipHash: tip.hash)
          return (lookup, try lookup.lookUpNext())
        }
        var next = first
        while let account = next {
          if lookedUp == 0 {
            let seconds = HeaderSyncBenchmark.uptime() - restoreStart
            timeToFirstBalanceSeconds = seconds
            context.note("timeToFirstBalanceSeconds", String(format: "%.3f", seconds))
          }
          lookedUp += 1
          if account.used {
            context.note("balance.\(account.index)", account.balance)
          }
          next = try lookup.lookUpNext()
        }
        return lookup
      }
      context.note("accountsLookedUp", String(lookedUp))
      context.note("restoreSeconds", String(format: "%.3f", HeaderSyncBenchmark.uptime() - restoreStart))

      let expected = TestChainConfig.restoreAccountsExpected
      context.note("accountsExpected", String(expected))
      let result = restore.result()
      context.note("scanComplete", result.complete ? "true" : "false")
      context.note("balanceNote", result.note)
      context.note("balancesVerified", result.accounts.contains { $0.unverified } ? "false" : "true")
      let used = result.accounts.filter { $0.used }
      context.note("accountsFound", String(used.count))
      context.note("accountsFoundIndexes", used.map { String($0.index) }.joined(separator: ","))

      guard result.complete else {
        throw RestoreBenchmarkError.notComplete
      }
      if expected == 0 {
        throw RestoreBenchmarkError.expectedNotSet(found: used.count)
      }
      if used.count != expected {
        throw RestoreBenchmarkError.accountsMissing(found: used.count, expected: expected)
      }
      guard let firstBalance = timeToFirstBalanceSeconds else {
        throw RestoreBenchmarkError.noBalance
      }
      if firstBalance > firstBalanceLimitSeconds {
        throw RestoreBenchmarkError.firstBalanceSlow(
          seconds: firstBalance, limit: firstBalanceLimitSeconds)
      }
    #else
      throw RestoreBenchmarkError.bindingsMissing
    #endif
  }
}

#if GHOST_CORE_BINDINGS
  /// The restore's account lookup on the test node: an account's balance
  /// and nonce at one block hash, as one JSON-RPC batch of eth_getBalance and
  /// eth_getTransactionCount. The core calls it off the main thread; each
  /// call waits for its answer.
  final class NodeAccountLookup: AccountLookup {
    private let url: URL
    private let session: URLSession

    init(url: URL) {
      self.url = url
      let configuration = URLSessionConfiguration.ephemeral
      configuration.timeoutIntervalForRequest = TestChainConfig.requestTimeoutSeconds
      session = URLSession(configuration: configuration)
    }

    func accountState(address: Data, blockHash: Data) throws -> AccountState {
      do {
        // The block by hash, and only if it is on the node's canonical chain.
        let block: [String: Any] = ["blockHash": "0x" + Hex.encode(blockHash), "requireCanonical": true]
        let account = "0x" + Hex.encode(address)
        let answers = try batch([
          ("eth_getBalance", [account, block]),
          ("eth_getTransactionCount", [account, block]),
        ])
        guard let balanceText = answers[0] as? String,
          let balance = Hex.decode(balanceText, quantity: true)
        else {
          throw RestoreBenchmarkError.node("a balance is not a hex quantity")
        }
        guard let nonceText = answers[1] as? String, let nonce = Hex.quantity(nonceText) else {
          throw RestoreBenchmarkError.node("a nonce is not a hex quantity")
        }
        return AccountState(balance: balance, nonce: nonce)
      } catch let error as RestoreError {
        throw error
      } catch {
        throw RestoreError.Lookup(reason: error.localizedDescription)
      }
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
