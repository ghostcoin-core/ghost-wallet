import Foundation

/// Everything the node benchmarks trust, in one place: the test node they
/// talk to, the accounts the restore must find and the minimum difficulty
/// the spot check holds a header to.
///
/// The compiled-in values stay as shipped; a test run against another chain
/// sets the test-only UserDefaults overrides in `OverrideKey` instead of
/// editing this file. Everything here is public chain data; nothing secret
/// belongs in this file.
enum TestChainConfig {
  /// The UserDefaults key holding the test node's JSON-RPC URL, for example
  /// "http://192.168.1.20:8545". Set it on the phone, not in the build.
  static let nodeUrlKey = "benchNodeUrl"

  /// Test-only overrides, read from UserDefaults on the phone or simulator
  /// and never from the build. scripts/sim-test.sh writes them for the local
  /// test chain of scripts/test-chain.sh, and scripts/phone-launch.sh passes
  /// them at launch (they land in UserDefaults' argument domain for that
  /// launch); with none set, the compiled values below are used.
  enum OverrideKey {
    /// The accounts the restore benchmark must find (integer).
    static let restoreAccountsExpected = "benchTestChain.restoreAccountsExpected"
  }

  /// The compiled-in values, used when no override is set.
  enum Compiled {
    /// PLACEHOLDER: set it to the number of accounts used when the test
    /// wallet was set up.
    static let restoreAccountsExpected = 0
  }

  /// The lowest difficulty the spot check accepts for a header: the test
  /// chain's own floor (difficulty 1, spec 06, section 4.2). A release pins
  /// its network's minimum instead.
  static let spotCheckMinDifficulty: UInt64 = 1

  /// The timeout of one request to the node.
  static let requestTimeoutSeconds: Double = 60

  /// How many accounts of the test words the restore benchmark must find:
  /// the accounts given activity on the test chain.
  static var restoreAccountsExpected: Int {
    overrideCount(OverrideKey.restoreAccountsExpected).flatMap { Int(exactly: $0) }
      ?? Compiled.restoreAccountsExpected
  }

  /// A non-negative integer override, written as a number or as decimal text.
  private static func overrideCount(_ key: String) -> UInt64? {
    guard let value = UserDefaults.standard.object(forKey: key) else { return nil }
    switch value {
    case let number as NSNumber:
      return number.int64Value >= 0 ? UInt64(number.int64Value) : nil
    case let text as String:
      return UInt64(text.trimmingCharacters(in: .whitespaces))
    default:
      return nil
    }
  }
}
