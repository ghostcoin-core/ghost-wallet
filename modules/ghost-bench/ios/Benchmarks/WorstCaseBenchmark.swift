import Foundation

enum WorstCaseBenchmarkError: LocalizedError {
  case bindingsMissing
  case noNodeUrl
  case badNodeUrl
  case cachesNotLoaded(cacheCount: UInt64, bestHeight: UInt64)
  case notVerified(Int)

  var errorDescription: String? {
    switch self {
    case .bindingsMissing:
      return "The Swift bindings of the native core (ghost_wallet_core) are not in this build."
    case .noNodeUrl:
      return "No test node is set: put its JSON-RPC URL in the UserDefaults key "
        + "\(TestChainConfig.nodeUrlKey)."
    case .badNodeUrl:
      return "The test node URL in \(TestChainConfig.nodeUrlKey) is not an http or https URL."
    case .cachesNotLoaded(let count, let height):
      return "HeaderSync held \(count) RandomX caches, not 2, after checking every header up to "
        + "the node's tip (height \(height)). The test chain may be too short to cross a key "
        + "block change."
    case .notVerified(let index):
      return "Proof \(index) did not verify with Ghost's verifier."
    }
  }
}

/// A stress benchmark only: both 256 MiB RandomX caches held by HeaderSync
/// and a Summon proof running at once. The app never does this in its normal
/// path: it calls HeaderSync.releaseCaches() before a proof starts, so the
/// caches and the prover are not held together. This measures the headroom
/// if they ever are; it is not a requirement (note `workerStress`).
///
/// Stage `sync` builds a HeaderSync from the node and the start pinned in
/// TestChainConfig.swift (as the header-sync benchmark does) and checks
/// headers in a header run until it holds 2 caches. Keeping that HeaderSync
/// alive, stages `prove-1` to `prove-3` each prove one test Summon back to
/// back, checked with Ghost's verifier, and the cache count is read after
/// each proof. The caches are then released as the normal path does. The
/// harness records peak memory, memory warnings, kills and heat for the run.
enum WorstCaseBenchmark {
  static let name = "worst-case"

  static let kind = "stress benchmark only"

  static let runs = 3

  /// Both RandomX caches: the current key block's and the next one's.
  static let wantedCaches: UInt64 = 2

  static func run(_ context: BenchContext) throws {
    #if GHOST_CORE_BINDINGS
      context.note("randomx", "interpreted, light caches, no JIT")
      context.note("benchmarkKind", kind)
      context.note("workerStress", "true")
      guard
        let text = UserDefaults.standard.string(forKey: TestChainConfig.nodeUrlKey), !text.isEmpty
      else {
        throw WorstCaseBenchmarkError.noNodeUrl
      }
      guard let url = URL(string: text), url.scheme == "http" || url.scheme == "https" else {
        throw WorstCaseBenchmarkError.badNodeUrl
      }
      let node = TestNodeClient(url: url)
      let sync: HeaderSync = try HeaderSyncBenchmark.makeSync(node: node, context: context)
      context.note("startHeight", String(sync.bestHeight()))

      try context.stage("sync") {
        let tip = try node.blockNumber()
        context.note("nodeTipAtStart", String(tip))
        var tally = HeaderSyncBenchmark.Tally()
        let run = sync.startRun(
          budget: HeaderSyncBenchmark.runBudget, conditions: HeaderSyncBenchmark.conditions())
        // One batch at a time, stopping as soon as both caches are held.
        while sync.cacheCount() < wantedCaches && sync.bestHeight() < tip {
          let target = min(tip, sync.bestHeight() + UInt64(TestChainConfig.batchSize))
          try HeaderSyncBenchmark.syncThrough(
            target, sync: sync, run: run, node: node, context: context, tally: &tally)
        }
        context.note("syncedHeaders", String(tally.accepted))
      }
      let before = sync.cacheCount()
      context.note("cacheCountBeforeProve", String(before))
      context.note("bestHeight", String(sync.bestHeight()))
      guard before == wantedCaches else {
        throw WorstCaseBenchmarkError.cachesNotLoaded(cacheCount: before, bestHeight: sync.bestHeight())
      }

      var verifiedCount = 0
      context.note("runs", String(runs))
      context.note("verifiedCount", "0")
      for index in 1...runs {
        let report = try context.stage("prove-\(index)") { try proveTestSummon() }
        context.note("proveMillis-\(index)", String(report.proveMillis))
        context.note("cacheCountAfterProve-\(index)", String(sync.cacheCount()))
        if report.verified {
          verifiedCount += 1
        }
        context.note("verifiedCount", String(verifiedCount))
        if !report.verified {
          throw WorstCaseBenchmarkError.notVerified(index)
        }
      }
      // Keeps HeaderSync, and its caches, alive through the last proof, then
      // frees them as the normal path does before a proof.
      withExtendedLifetime(sync) {}
      context.note("cachesReleased", sync.releaseCaches() ? "true" : "false")
      context.note("cacheCountAfterRelease", String(sync.cacheCount()))
    #else
      throw WorstCaseBenchmarkError.bindingsMissing
    #endif
  }
}
