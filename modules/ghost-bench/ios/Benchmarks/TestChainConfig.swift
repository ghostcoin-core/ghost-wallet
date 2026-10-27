import Foundation

/// Everything the header-sync benchmark trusts, in one place: the test node it
/// talks to, the start it pins and the chain constants it checks against.
///
/// The compiled-in values stay as shipped; a test run against another chain
/// sets the test-only UserDefaults overrides in `OverrideKey` instead of
/// editing this file. Everything here is public chain data; nothing secret
/// belongs in this file.
enum TestChainConfig {
  /// The UserDefaults key holding the test node's JSON-RPC URL, for example
  /// "http://192.168.1.20:8545". Set it on the phone, not in the build.
  static let nodeUrlKey = "benchNodeUrl"

  /// Where the header chain starts.
  enum Start {
    /// The genesis header, as hex of its 19-field RLP (spec 05, section 10).
    case genesis(rlpHex: String)
    /// A pinned checkpoint: its RLP as hex, its height, the total work up to
    /// and including it (hex, big-endian), the genesis timestamp, and the
    /// key blocks below it that the headers after it use, as
    /// (height, 32-byte hash as hex).
    case checkpoint(
      rlpHex: String, height: UInt64, totalWorkHex: String, genesisTimestamp: UInt64,
      keyBlocks: [(height: UInt64, hashHex: String)])
  }

  /// Test-only overrides, read from UserDefaults on the phone or simulator
  /// and never from the build. scripts/sim-test.sh writes them for the local
  /// test chain of scripts/test-chain.sh; with none set, the compiled values
  /// below are used.
  enum OverrideKey {
    /// Block time in seconds (integer).
    static let blockTime = "benchTestChain.blockTime"
    /// Future drift in seconds (integer).
    static let futureDrift = "benchTestChain.futureDrift"
    /// The genesis header's RLP as hex, pinned as the start.
    static let genesisRlpHex = "benchTestChain.genesisRlpHex"
    /// The accounts the restore benchmark must find (integer).
    static let restoreAccountsExpected = "benchTestChain.restoreAccountsExpected"
  }

  /// The compiled-in values, used when no override is set.
  enum Compiled {
    /// PLACEHOLDER: the test chain's genesis header is not known yet. Leave it
    /// empty and run the benchmark once: it fails, and records the header the
    /// node reports for block 0 in the note `nodeGenesisRlpHex`. Check that
    /// header against the test chain's known genesis hash, then paste it here.
    static let start: Start = .genesis(rlpHex: "")

    /// PLACEHOLDER: Ghost's internal network test constants (30-second
    /// blocks); replace them if the test chain uses others.
    static let blockTime: UInt64 = 30
    static let futureDrift: UInt64 = 30

    /// PLACEHOLDER: set it to the number of accounts used when the test
    /// wallet was set up.
    static let restoreAccountsExpected = 0
  }

  /// The pinned start: the genesis override if set, else the compiled one.
  static var start: Start {
    if let rlpHex = overrideString(OverrideKey.genesisRlpHex) {
      return .genesis(rlpHex: rlpHex)
    }
    return Compiled.start
  }

  /// The chain constants of spec 06, section 4.2 (difficulty 1).
  static var blockTime: UInt64 {
    overrideCount(OverrideKey.blockTime).flatMap { $0 > 0 ? $0 : nil } ?? Compiled.blockTime
  }
  static let halfLife: UInt64 = 3600
  static let startDifficulty: UInt64 = 1
  static let minDifficulty: UInt64 = 1
  static var futureDrift: UInt64 {
    overrideCount(OverrideKey.futureDrift) ?? Compiled.futureDrift
  }

  /// Headers asked for in one JSON-RPC batch.
  static let batchSize = 100

  /// Headers below the tip left for the resume stage: the sync stops this
  /// many short, and the resume stage fetches them (and any mined since).
  static let resumeHeaders: UInt64 = 200

  /// How long the benchmark waits for the app to be backgrounded and brought
  /// back before it resumes anyway.
  static let backgroundWaitSeconds: Double = 180

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

  /// A non-empty text override.
  private static func overrideString(_ key: String) -> String? {
    guard let text = UserDefaults.standard.string(forKey: key)?
      .trimmingCharacters(in: .whitespacesAndNewlines), !text.isEmpty
    else { return nil }
    return text
  }
}
