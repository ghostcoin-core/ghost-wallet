import Darwin
import Foundation

#if canImport(ghost_wallet_core)
  import ghost_wallet_core
#endif

enum KillRecoveryBenchmarkError: LocalizedError {
  case bindingsMissing
  case unknownKillPoint(String)
  case notRecovered(String)
  case noSettle

  var errorDescription: String? {
    switch self {
    case .bindingsMissing:
      return "The Swift bindings of the native core (ghost_wallet_core) are not in this build."
    case .unknownKillPoint(let value):
      return "The UserDefaults key \(KillRecoveryBenchmark.killPointKey) holds \(value): use none, all, "
        + KillRecoveryBenchmark.KillPoint.allCases.map(\.rawValue).joined(separator: ", ") + "."
    case .notRecovered(let outcome):
      return "A kill point did not recover cleanly: \(outcome)."
    case .noSettle:
      return "The payment did not settle."
    }
  }
}

/// Survives being killed mid-step: a test-chain payment moved through the
/// native step sequence (prepared, backed up, signed, sent, seen, settled),
/// every step saved in the Keychain (KeychainStepStore) before its effect, the
/// signed bytes saved before the send.
///
/// The kill point is read from the UserDefaults key `benchKillPoint`: `none`,
/// one of the six steps (`prepared`, `backed-up`, `signed`, `sent`, `seen`,
/// `settled`: killed right after that step is saved), `after-broadcast`
/// (killed after the broadcast, before its reply is handled), or `all` (the
/// first kill point with no outcome yet, so run, relaunch, run again walks
/// through every one). `benchKillSignal` picks how: `sigkill` (the default,
/// `kill(getpid(), SIGKILL)`) or `exit` (`exit(0)`). A `kill -9` from the
/// Mac at any moment is recovered the same way, under `external`.
///
/// On the next launch `recoverAtLaunch` (called by the module as it loads)
/// opens every unfinished record, asks the native `recover` what to do and
/// does it, until the payment settles: resending only the stored bytes, and
/// only when the chain does not have them. It checks that the payment is on
/// the chain exactly once, broadcast once, with the hash it had at the kill,
/// and times it. The next run writes the table into its notes:
/// `killPoint.<name>` = outcome and `recoveryMs.<name>`.
///
/// The test chain has no send call yet, so the payment goes to a fake chain
/// kept in a file in the app's Documents (it survives the kill, counts every
/// broadcast and mines a block on each); the note `chain` says so. The
/// "signed" transaction is synthetic test bytes: no key and no funds.
enum KillRecoveryBenchmark {
  static let name = "kill-recovery"
  static let killPointKey = "benchKillPoint"
  static let killSignalKey = "benchKillSignal"

  /// Where a run ends the process: right after the step is saved, or after
  /// the broadcast before its reply.
  enum KillPoint: String, CaseIterable, Codable {
    case prepared
    case backedUp = "backed-up"
    case signed
    case sent
    case afterBroadcast = "after-broadcast"
    case seen
    case settled
  }

  static let chainNote =
    "fake: the test chain has no send call yet, so a file-backed fake chain in Documents stands in"

  /// What survives a kill besides the Keychain: the armed kill point and the
  /// outcome table. Written atomically before every kill.
  struct State: Codable {
    struct Armed: Codable {
      var point: String
      var id: String
      var hashHex: String?
    }

    var armed: Armed?
    var outcomes: [String: String] = [:]
    var recoveryMs: [String: String] = [:]
    var launchToRecoveredMs: [String: String] = [:]
  }

  static var stateURL: URL { ResultsStore.documents.appendingPathComponent("kill-recovery-state.json") }

  static func loadState() -> State {
    guard let data = try? Data(contentsOf: stateURL),
      let state = try? JSONDecoder().decode(State.self, from: data)
    else { return State() }
    return state
  }

  static func saveState(_ state: State) {
    guard let data = try? JSONEncoder().encode(state) else { return }
    try? data.write(to: stateURL, options: .atomic)
  }

  static func run(_ context: BenchContext) throws {
    #if canImport(ghost_wallet_core)
      context.note("chain", chainNote)
      context.note("store", "Keychain, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, not synchronizable")
      let chain = FakeTestChain()
      let store = KeychainStepStore()

      // Anything launch recovery could not finish (the phone was locked, say).
      try context.stage("recover") {
        _ = recoverUnfinished(store: store, chain: chain, launchStart: nil)
      }
      context.stage("tamper") {
        context.note("tamperedRecord", tamperCheck(store: store))
      }

      var state = loadState()
      for (point, outcome) in state.outcomes {
        context.note("killPoint.\(point)", outcome)
      }
      for (point, ms) in state.recoveryMs {
        context.note("recoveryMs.\(point)", ms)
      }
      for (point, ms) in state.launchToRecoveredMs {
        context.note("launchToRecoveredMs.\(point)", ms)
      }
      let failed = state.outcomes.filter { !$0.value.hasPrefix("ok") }
      context.note(
        "killPointsPassed",
        "\(state.outcomes.count - failed.count) of \(KillPoint.allCases.count) kill points recorded")

      let setting = UserDefaults.standard.string(forKey: killPointKey) ?? "none"
      let point: KillPoint?
      switch setting {
      case "", "none":
        point = nil
      case "all":
        point = KillPoint.allCases.first { state.outcomes[$0.rawValue]?.hasPrefix("ok") != true }
      default:
        guard let chosen = KillPoint(rawValue: setting) else {
          throw KillRecoveryBenchmarkError.unknownKillPoint(setting)
        }
        point = chosen
      }
      context.note("killPointArmed", point?.rawValue ?? "none")

      let id = "bench-" + UUID().uuidString.lowercased()
      state.armed = point.map { State.Armed(point: $0.rawValue, id: id, hashHex: nil) }
      saveState(state)

      try context.stage("payment") {
        let sequence = try StepSequence.start(store: store, id: id)
        try kill(at: .prepared, armed: point, sequence: sequence, context: context)
        try drive(sequence, chain: chain, kill: point, context: context)
      }

      // Not killed: it settled in this run.
      let outcome = check(id: id, store: store, chain: chain, hashAtKill: nil)
      context.note("killPoint.none", outcome)
      state = loadState()
      state.armed = nil
      saveState(state)
      if !outcome.hasPrefix("ok") {
        throw KillRecoveryBenchmarkError.notRecovered(outcome)
      }
      if !failed.isEmpty {
        throw KillRecoveryBenchmarkError.notRecovered(
          failed.map { "\($0.key): \($0.value)" }.sorted().joined(separator: "; "))
      }
    #else
      throw KillRecoveryBenchmarkError.bindingsMissing
    #endif
  }

  /// Called by the module as the app launches: recovers any payment a kill
  /// left unfinished, and keeps the outcome for the next run's notes.
  static func recoverAtLaunch() {
    #if canImport(ghost_wallet_core)
      _ = recoverUnfinished(store: KeychainStepStore(), chain: FakeTestChain(), launchStart: processStartDate())
    #endif
  }

  /// When this process started, from the kernel.
  static func processStartDate() -> Date? {
    var info = kinfo_proc()
    var size = MemoryLayout<kinfo_proc>.stride
    var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
    guard sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0) == 0 else { return nil }
    let start = info.kp_proc.p_un.__p_starttime
    return Date(timeIntervalSince1970: Double(start.tv_sec) + Double(start.tv_usec) / 1_000_000)
  }

  #if canImport(ghost_wallet_core)
    /// Opens every unfinished record and drives it to settled. A record that
    /// cannot be opened or recovered is an outcome to show; it is kept as it
    /// is and nothing is sent for it. Returns how many were found.
    static func recoverUnfinished(store: KeychainStepStore, chain: FakeTestChain, launchStart: Date?) -> Int {
      let start = HeaderSyncBenchmark.uptime()
      var state = loadState()
      let ids: [String]
      do {
        ids = try store.list()
      } catch {
        if let armed = state.armed {
          state.outcomes[armed.point] = "error: the records could not be listed: \(error)"
          saveState(state)
        }
        return 0
      }

      for id in ids {
        let armed = state.armed?.id == id ? state.armed : nil
        let point = armed?.point ?? "external"
        let outcome: String
        do {
          let sequence = try StepSequence.open(store: store, id: id)
          try drive(sequence, chain: chain, kill: nil, context: nil)
          outcome = check(id: id, store: store, chain: chain, hashAtKill: armed?.hashHex)
        } catch {
          outcome = "refused, kept and not sent: \(error)"
        }
        let ms = (HeaderSyncBenchmark.uptime() - start) * 1000
        state.outcomes[point] = outcome
        state.recoveryMs[point] = String(format: "%.1f", ms)
        if let launched = launchStart {
          state.launchToRecoveredMs[point] = String(format: "%.1f", Date().timeIntervalSince(launched) * 1000)
        }
        if armed != nil {
          state.armed = nil
        }
      }

      // Armed, but its record is gone: lost unless the chain has it once.
      if let armed = state.armed, !ids.contains(armed.id) {
        let paid = chain.payments(for: armed.id)
        state.outcomes[armed.point] =
          paid.count == 1
          ? "ok: paid once, record already removed"
          : "FAILED: the record is gone and the chain has \(paid.count) payments"
        state.armed = nil
      }
      saveState(state)
      return ids.count
    }

    /// The payment is on the chain exactly once, broadcast once, with the
    /// hash it had at the kill, settled, and its record removed.
    static func check(id: String, store: KeychainStepStore, chain: FakeTestChain, hashAtKill: String?) -> String {
      let paid = chain.payments(for: id)
      guard paid.count == 1, let hash = paid.first else {
        return "FAILED: the chain has \(paid.count) payments for it"
      }
      let broadcasts = chain.broadcasts(of: hash)
      if broadcasts != 1 {
        return "FAILED: broadcast \(broadcasts) times"
      }
      if let before = hashAtKill, before != hash {
        return "FAILED: the transaction hash changed"
      }
      if (try? store.load(id: id)) != nil {
        return "FAILED: the record is still there"
      }
      if chain.confirmations(ofHex: hash) < settleConfirmations() {
        return "FAILED: not settled"
      }
      return "ok: paid once, 1 broadcast, same hash"
    }

    /// Does what `recover` says until the payment is settled and removed.
    /// Only the stored bytes are ever sent, and only when the chain does not
    /// have them.
    static func drive(
      _ sequence: StepSequence, chain: FakeTestChain, kill point: KillPoint?, context: BenchContext?
    ) throws {
      let id = sequence.record().id
      for _ in 0..<100 {
        switch try sequence.recover(chain: chain) {
        case .done:
          try sequence.finish()
          return
        case .resume(let step):
          switch step {
          case .prepared:
            throw KillRecoveryBenchmarkError.noSettle
          case .backedUp:
            try sequence.markBackedUp()
            try kill(at: .backedUp, armed: point, sequence: sequence, context: context)
          case .signed:
            _ = try sequence.markSigned(signedTransaction: syntheticSend(id: id))
            try kill(at: .signed, armed: point, sequence: sequence, context: context)
          case .sent:
            try sequence.markSent()
            try kill(at: .sent, armed: point, sequence: sequence, context: context)
          case .seen:
            try sequence.markSeen(chain: chain)
            try kill(at: .seen, armed: point, sequence: sequence, context: context)
          case .settled:
            try sequence.markSettled(chain: chain)
            try kill(at: .settled, armed: point, sequence: sequence, context: context)
          }
        case .resendSame(let bytes):
          if sequence.step() == .signed {
            try sequence.markSent()
            try kill(at: .sent, armed: point, sequence: sequence, context: context)
          }
          chain.broadcast(bytes)
          try kill(at: .afterBroadcast, armed: point, sequence: sequence, context: context)
        case .wait:
          chain.mine()
        }
      }
      throw KillRecoveryBenchmarkError.noSettle
    }

    /// Ends the process if this is the armed kill point, after saving the
    /// record's hash and flushing the run's notes.
    static func kill(at here: KillPoint, armed: KillPoint?, sequence: StepSequence, context: BenchContext?)
      throws
    {
      guard here == armed, let context = context else { return }
      var state = loadState()
      state.armed?.hashHex = sequence.record().transactionHash.map { Hex.encode($0) }
      saveState(state)
      let signal = UserDefaults.standard.string(forKey: killSignalKey) ?? "sigkill"
      context.note("killedAt", here.rawValue)
      context.note("killedWith", signal == "exit" ? "exit(0)" : "SIGKILL")
      BenchRunner.flushPending()
      if signal == "exit" {
        exit(0)
      }
      Darwin.kill(getpid(), SIGKILL)
    }

    /// A synthetic test-chain send: test bytes naming the payment and a fresh
    /// nonce, so signing twice would show as a second payment.
    static func syntheticSend(id: String) -> Data {
      Data("synthetic test-chain send \(id) nonce \(UUID().uuidString)".utf8)
    }

    /// Saves a damaged record and checks it is refused, then removes it.
    static func tamperCheck(store: KeychainStepStore) -> String {
      let id = "bench-tamper-check"
      defer { try? store.remove(id: id) }
      do {
        try? store.remove(id: id)
        let sequence = try StepSequence.start(store: store, id: id)
        try sequence.markBackedUp()
        var bytes = encodeStepRecord(record: sequence.record())
        bytes[bytes.count - 1] ^= 0x01
        try store.saveRaw(id: id, bytes: bytes)
        _ = try StepSequence.open(store: store, id: id)
        return "FAILED: a damaged record was accepted"
      } catch StepError.Tampered(_, let reason) {
        return "refused: \(reason)"
      } catch {
        return "FAILED: \(error)"
      }
    }
  #endif
}

#if canImport(ghost_wallet_core)
  /// A stand-in for the test chain, kept in a file so it survives the kill:
  /// a broadcast transaction goes into the next block (once), every
  /// broadcast is counted, and `mine` adds an empty block.
  final class FakeTestChain: ChainView {
    struct Ledger: Codable {
      var height: UInt64 = 0
      /// Block height of every included transaction, by hash (hex).
      var included: [String: UInt64] = [:]
      /// The payment id each included transaction names, by hash (hex).
      var payments: [String: String] = [:]
      var broadcasts: [String: Int] = [:]
    }

    private let lock = NSLock()
    let url: URL

    init(url: URL = ResultsStore.documents.appendingPathComponent("kill-recovery-chain.json")) {
      self.url = url
    }

    private func read() -> Ledger {
      guard let data = try? Data(contentsOf: url),
        let ledger = try? JSONDecoder().decode(Ledger.self, from: data)
      else { return Ledger() }
      return ledger
    }

    private func change(_ body: (inout Ledger) -> Void) {
      lock.lock()
      defer { lock.unlock() }
      var ledger = read()
      body(&ledger)
      if let data = try? JSONEncoder().encode(ledger) {
        try? data.write(to: url, options: .atomic)
      }
    }

    func broadcast(_ bytes: Data) {
      let hash = Hex.encode(transactionHash(signedTransaction: bytes))
      let text = String(decoding: bytes, as: UTF8.self)
      let id = text.split(separator: " ").first { $0.hasPrefix("bench-") }.map(String.init) ?? ""
      change { ledger in
        ledger.broadcasts[hash, default: 0] += 1
        if ledger.included[hash] == nil {
          ledger.height += 1
          ledger.included[hash] = ledger.height
          ledger.payments[hash] = id
        }
      }
    }

    func mine() {
      change { $0.height += 1 }
    }

    func payments(for id: String) -> [String] {
      lock.lock()
      defer { lock.unlock() }
      return read().payments.filter { $0.value == id }.map(\.key)
    }

    func broadcasts(of hashHex: String) -> Int {
      lock.lock()
      defer { lock.unlock() }
      return read().broadcasts[hashHex] ?? 0
    }

    func confirmations(ofHex hashHex: String) -> UInt64 {
      lock.lock()
      defer { lock.unlock() }
      let ledger = read()
      guard let at = ledger.included[hashHex] else { return 0 }
      return ledger.height - at + 1
    }

    func hasTransaction(hash: Data) throws -> Bool {
      confirmations(ofHex: Hex.encode(hash)) > 0
    }

    func confirmations(hash: Data) throws -> UInt64 {
      confirmations(ofHex: Hex.encode(hash))
    }
  }
#endif
