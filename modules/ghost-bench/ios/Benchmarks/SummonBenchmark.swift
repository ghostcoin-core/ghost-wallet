import Foundation

enum SummonBenchmarkError: LocalizedError {
  case bindingsMissing
  case notVerified(Int)

  var errorDescription: String? {
    switch self {
    case .bindingsMissing:
      return "The Swift bindings of the native core (ghost_wallet_core) are not in this build."
    case .notVerified(let index):
      return "Proof \(index) did not verify with Ghost's verifier."
    }
  }
}

/// Proves one Summon (a reveal of a salted coin, with Ghost's own reveal
/// builder) on the fixed test chain, five times back to back, to see heat
/// throttling. Each proof is checked with Ghost's verifier on the phone.
/// The test key and chain are built in the native core; nothing touches
/// real funds.
enum SummonBenchmark {
  static let name = "summon"

  static let runs = 5

  static func run(_ context: BenchContext) throws {
    #if GHOST_CORE_BINDINGS
      var verifiedCount = 0
      context.note("runs", String(runs))
      context.note("verifiedCount", "0")
      for index in 1...runs {
        let report = try context.stage("prove-\(index)") { try proveTestSummon() }
        context.note("proofBytes", String(report.proofBytes))
        context.note("proveMillis-\(index)", String(report.proveMillis))
        if report.verified {
          verifiedCount += 1
        }
        context.note("verifiedCount", String(verifiedCount))
        if !report.verified {
          throw SummonBenchmarkError.notVerified(index)
        }
      }
    #else
      throw SummonBenchmarkError.bindingsMissing
    #endif
  }
}
