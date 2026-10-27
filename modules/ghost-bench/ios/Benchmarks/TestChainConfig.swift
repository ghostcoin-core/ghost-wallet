import Foundation

/// Everything the header-sync benchmark trusts, in one place: the test node it
/// talks to, the start it pins and the chain constants it checks against.
///
/// Fill these in by hand for the test chain before running the benchmark.
/// Everything here is public chain data; nothing secret belongs in this file.
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

  /// PLACEHOLDER: the test chain's genesis header is not known yet. Leave it
  /// empty and run the benchmark once: it fails, and records the header the
  /// node reports for block 0 in the note `nodeGenesisRlpHex`. Check that
  /// header against the test chain's known genesis hash, then paste it here.
  static let start: Start = .genesis(rlpHex: "")

  /// The chain constants of spec 06, section 4.2. PLACEHOLDER: these are
  /// Ghost's internal network test constants (difficulty 1, 30-second
  /// blocks); replace them if the test chain uses others.
  static let blockTime: UInt64 = 30
  static let halfLife: UInt64 = 3600
  static let startDifficulty: UInt64 = 1
  static let minDifficulty: UInt64 = 1
  static let futureDrift: UInt64 = 30

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
  /// the accounts given activity on the test chain by hand. PLACEHOLDER:
  /// set it to the number of accounts used when the test wallet was set up.
  static let restoreAccountsExpected = 0
}
