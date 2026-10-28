import Foundation

enum WorstCaseBenchmarkError: LocalizedError {
  case bindingsMissing
  case cacheNotHeld(String)
  case notVerified(Int)

  var errorDescription: String? {
    switch self {
    case .bindingsMissing:
      return "The Swift bindings of the native core (ghost_wallet_core) are not in this build."
    case .cacheNotHeld(let when):
      return "The spot check's RandomX cache was not held \(when)."
    case .notVerified(let index):
      return "Proof \(index) did not verify with Ghost's verifier."
    }
  }
}

/// A stress benchmark only: one 256 MiB RandomX spot-check cache held while
/// Summon proofs run. The app never does this in its normal path: a spot
/// check frees its cache before it returns, so the cache and the prover are
/// not held together. This measures the headroom if they ever are; it is not
/// a requirement (note `workerStress`).
///
/// Stage `spot check` fetches the node's tip header and its key block's hash
/// (as the header-sync benchmark does), builds the cache of that key block
/// with the native core's SpotCheckKey and checks the tip once under it. Any
/// tip above block 0 will do: the chain need not reach a second RandomX key.
/// Keeping that cache, stages `prove-1` to `prove-3` each prove one test
/// Summon back to back, checked with Ghost's verifier, and the cache is
/// checked to be still held after each proof. The cache is then released.
/// The harness records peak memory, memory warnings, kills and heat for the
/// run.
enum WorstCaseBenchmark {
  static let name = "worst-case"

  static let kind = "stress benchmark only"

  static let runs = 3

  /// The RandomX caches held through the proofs: the spot check's one.
  static let wantedCaches: UInt64 = 1

  static func run(_ context: BenchContext) throws {
    #if GHOST_CORE_BINDINGS
      context.note("randomx", "interpreted, light caches, no JIT")
      context.note("benchmarkKind", kind)
      context.note("workerStress", "true")
      let node = try HeaderSyncBenchmark.nodeClient()
      let tip = try context.stage("fetch") { try HeaderSyncBenchmark.fetchTip(node: node, context: context) }

      let key = try context.stage("spot check") { () -> SpotCheckKey in
        let key = try SpotCheckKey(keyBlockHash: tip.keyBlockHash)
        let report = try key.check(
          header: tip.header, minDifficulty: HeaderSyncBenchmark.minDifficulty())
        HeaderSyncBenchmark.noteSpotCheck(report, context: context)
        try HeaderSyncBenchmark.requirePassed(report, tip: tip)
        return key
      }
      let before: UInt64 = key.isHeld() ? 1 : 0
      context.note("cacheCountBeforeProve", String(before))
      guard before == wantedCaches else {
        throw WorstCaseBenchmarkError.cacheNotHeld("before the proofs")
      }

      var verifiedCount = 0
      context.note("runs", String(runs))
      context.note("verifiedCount", "0")
      for index in 1...runs {
        let report = try context.stage("prove-\(index)") { try proveTestSummon() }
        context.note("proveMillis-\(index)", String(report.proveMillis))
        context.note("cacheCountAfterProve-\(index)", key.isHeld() ? "1" : "0")
        if report.verified {
          verifiedCount += 1
        }
        context.note("verifiedCount", String(verifiedCount))
        if !report.verified {
          throw WorstCaseBenchmarkError.notVerified(index)
        }
      }
      // The cache was held through the last proof; only now is it freed.
      guard key.isHeld() else {
        throw WorstCaseBenchmarkError.cacheNotHeld("through the proofs")
      }
      context.note("cachesReleased", key.release() ? "true" : "false")
      context.note("cacheCountAfterRelease", key.isHeld() ? "1" : "0")
      HeaderSyncBenchmark.noteDevice(context: context)
    #else
      throw WorstCaseBenchmarkError.bindingsMissing
    #endif
  }
}
