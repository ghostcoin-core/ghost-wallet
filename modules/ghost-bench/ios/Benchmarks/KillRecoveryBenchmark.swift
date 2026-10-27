import Darwin
import Foundation

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

/// Survives being killed mid-step: a test-chain send moved through the
/// native payment state machine (prepared, backed up, signed, sent, included,
/// settled), every step saved before its effect. The small record is in the
/// Keychain; the signed bytes, about 1.3 MB like a proof, are an encrypted
/// payload in protected app storage (KeychainStepStore), written before the
/// record lists them.
///
/// The kill point is read from the UserDefaults key `benchKillPoint`: `none`,
/// one of the six steps (`prepared`, `backed-up`, `signed`, `sent`,
/// `included`, `settled`: killed right after that step is saved),
/// `after-broadcast` (killed after the broadcast, before its reply is
/// handled), or `all` (the first kill point with no outcome yet, so run,
/// relaunch, run again walks through every one). `benchKillSignal` picks
/// how: `sigkill` (the default, `kill(getpid(), SIGKILL)`) or `exit`
/// (`exit(0)`). A `kill -9` from the Mac at any moment is recovered the same
/// way, under `external`.
///
/// On the next launch `recoverAtLaunch` (called by the module as it loads)
/// opens every unfinished record, asks the native `recover` what to do and
/// does it, until the payment settles: resending only the stored bytes, and
/// only when the chain does not have them. It checks that the payment is on
/// the chain exactly once, broadcast once, with the hash it had at the kill,
/// and that the settled record was kept with its block hash, and times it.
/// The benchmark then removes its own synthetic record. The next run writes
/// the table into its notes: `killPoint.<name>` = outcome and
/// `recoveryMs.<name>`.
///
/// The test chain has no send call yet, so the payment goes to a fake chain
/// kept in a file in the app's Documents (it survives the kill, counts every
/// broadcast and mines a block on each); the note `chain` says so. The
/// "signed" transaction is synthetic test bytes: no key and no funds.
enum KillRecoveryBenchmark {
  static let name = "kill-recovery"
  static let killPointKey = "benchKillPoint"
  static let killSignalKey = "benchKillSignal"

  /// The size of the synthetic signed transaction: about a Ghost proof.
  static let payloadBytes = 1_300_000

  /// Where a run ends the process: right after the step is saved, or after
  /// the broadcast before its reply.
  enum KillPoint: String, CaseIterable, Codable {
    case prepared
    case backedUp = "backed-up"
    case signed
    case sent
    case afterBroadcast = "after-broadcast"
    case included
    case settled
  }

  static let chainNote =
    "fake: the test chain has no send call yet, so a file-backed fake chain in Documents stands in"

  /// What survives a kill besides the store: the armed kill point and the
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
    #if GHOST_CORE_BINDINGS
      context.note("chain", chainNote)
      context.note(
        "store",
        "records: Keychain, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, not synchronizable; "
          + "signed bytes: AES-GCM with a Keychain key, completeFileProtection, atomic writes")
      context.note("payloadBytes", String(payloadBytes))
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
        let sequence = try PaymentSequence.start(store: store, id: id, intent: syntheticIntent())
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
    #if GHOST_CORE_BINDINGS
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

  #if GHOST_CORE_BINDINGS
    /// Opens every unfinished record and drives it to settled. A record that
    /// cannot be opened or recovered is an outcome to show; it is kept as it
    /// is and nothing is sent for it. A record already settled, failed or
    /// conflicted from an earlier run (kept because its check failed) is
    /// left alone unless it is the armed one. Returns how many were found.
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

      var found = 0
      for id in ids {
        let armed = state.armed?.id == id ? state.armed : nil
        let point = armed?.point ?? "external"
        let outcome: String
        do {
          let sequence = try PaymentSequence.open(store: store, id: id)
          if armed == nil, isFinal(sequence.step()) {
            continue
          }
          found += 1
          try drive(sequence, chain: chain, kill: nil, context: nil)
          outcome = check(id: id, store: store, chain: chain, hashAtKill: armed?.hashHex)
        } catch {
          found += 1
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
      return found
    }

    static func isFinal(_ step: Step) -> Bool {
      switch step {
      case .settled, .failed, .conflicted:
        return true
      default:
        return false
      }
    }

    /// The payment is on the chain exactly once, broadcast once, with the
    /// hash it had at the kill, settled, and its record kept as settled with
    /// the block hash. The benchmark's own synthetic record is then removed;
    /// a record that fails the check is kept to look at.
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
      if chain.confirmations(ofHex: hash) < settleConfirmations() {
        return "FAILED: not settled"
      }
      guard let record = try? store.load(id: id) else {
        return "FAILED: the settled record was not kept"
      }
      guard record.step == .settled, let inclusion = record.inclusion else {
        return "FAILED: the record is \(record.step), not settled"
      }
      if Hex.encode(inclusion.transactionHash) != hash || inclusion.blockHash != chain.blockHash(ofHex: hash) {
        return "FAILED: the record names another transaction or block"
      }
      try? store.remove(id: id)
      return "ok: paid once, 1 broadcast, same hash, settled record kept"
    }

    /// Does what `recover` says until the payment is settled. Only the
    /// stored bytes are ever sent, and only when the chain does not have
    /// them.
    static func drive(
      _ sequence: PaymentSequence, chain: FakeTestChain, kill point: KillPoint?, context: BenchContext?
    ) throws {
      let id = sequence.record().id
      for _ in 0..<100 {
        let before = sequence.step()
        let action = try sequence.recover(chain: chain)
        // The chain moved the record: included or settled was just saved.
        let now = sequence.step()
        if now != before {
          if now == .included {
            try kill(at: .included, armed: point, sequence: sequence, context: context)
          } else if now == .settled {
            try kill(at: .settled, armed: point, sequence: sequence, context: context)
          }
        }
        switch action {
        case .backUp:
          try sequence.markBackedUp()
          try kill(at: .backedUp, armed: point, sequence: sequence, context: context)
        case .sign, .rebuild:
          let send = syntheticSend(id: id, identity: sequence.record().intent.identity)
          _ = try sequence.addAttempt(signedTransaction: send, validUntil: nil)
          try kill(at: .signed, armed: point, sequence: sequence, context: context)
        case .send:
          let wasSigned = sequence.step() == .signed
          let bytes = try sequence.markSent()
          if wasSigned {
            try kill(at: .sent, armed: point, sequence: sequence, context: context)
          }
          chain.broadcast(bytes)
          try kill(at: .afterBroadcast, armed: point, sequence: sequence, context: context)
        case .wait:
          chain.mine()
        case .done(let step):
          guard step == .settled else {
            throw KillRecoveryBenchmarkError.notRecovered("the payment ended \(step)")
          }
          return
        }
      }
      throw KillRecoveryBenchmarkError.noSettle
    }

    /// Ends the process if this is the armed kill point, after saving the
    /// newest attempt's hash and flushing the run's notes.
    static func kill(at here: KillPoint, armed: KillPoint?, sequence: PaymentSequence, context: BenchContext?)
      throws
    {
      guard here == armed, let context = context else { return }
      var state = loadState()
      state.armed?.hashHex = sequence.record().attempts.last.map { Hex.encode($0.transactionHash) }
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

    /// A test-chain send from a synthetic account with a fresh nonce.
    static func syntheticIntent() -> PaymentIntent {
      PaymentIntent(
        kind: .send,
        identity: .accountNonce(account: Data("bench-test-account".utf8), nonce: UInt64.random(in: 1...UInt64(1 << 48))),
        details: Data("synthetic test-chain send of 1 to bench-test-account".utf8))
    }

    /// The identity as one word, as the fake chain reads it.
    static func identityWord(_ identity: Identity) -> String {
      switch identity {
      case .accountNonce(let account, let nonce):
        return "nonce:\(Hex.encode(account)):\(nonce)"
      case .revealMarker(let marker):
        return "marker:\(Hex.encode(marker))"
      }
    }

    /// A synthetic test-chain send of `payloadBytes`: a header naming the
    /// payment, its identity and a fresh attempt id (so signing twice would
    /// show as a second payment), then filler standing in for the proof.
    static func syntheticSend(id: String, identity: Identity) -> Data {
      var bytes = Data("synthetic test-chain send \(id) \(identityWord(identity)) \(UUID().uuidString) ".utf8)
      bytes.append(Data(repeating: 0x2e, count: payloadBytes - bytes.count))
      return bytes
    }

    /// Saves a damaged record and checks it is refused, then removes it.
    static func tamperCheck(store: KeychainStepStore) -> String {
      let id = "bench-tamper-check"
      defer { try? store.remove(id: id) }
      do {
        try? store.remove(id: id)
        let sequence = try PaymentSequence.start(store: store, id: id, intent: syntheticIntent())
        try sequence.markBackedUp()
        var bytes = encodePaymentRecord(record: sequence.record())
        bytes[bytes.count - 1] ^= 0x01
        try store.saveRaw(id: id, bytes: bytes)
        _ = try PaymentSequence.open(store: store, id: id)
        return "FAILED: a damaged record was accepted"
      } catch StepError.Tampered(_, let reason) {
        return "refused: \(reason)"
      } catch {
        return "FAILED: \(error)"
      }
    }
  #endif
}

#if GHOST_CORE_BINDINGS
  /// A stand-in for the test chain, kept in a file so it survives the kill:
  /// a broadcast transaction goes into the next block (once, and only if no
  /// transaction used its identity yet), every broadcast is counted, and
  /// `mine` adds an empty block. Every receipt is a success.
  final class FakeTestChain: ChainView {
    struct Ledger: Codable {
      var height: UInt64 = 0
      /// Block height of every included transaction, by hash (hex).
      var included: [String: UInt64] = [:]
      /// The payment id each included transaction names, by hash (hex).
      var payments: [String: String] = [:]
      /// The transaction hash (hex) that used each identity.
      var identities: [String: String] = [:]
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

    private func reading<T>(_ body: (Ledger) -> T) -> T {
      lock.lock()
      defer { lock.unlock() }
      return body(read())
    }

    func broadcast(_ bytes: Data) {
      let hash = Hex.encode(transactionHash(signedTransaction: bytes))
      // The header is the first line of words; the rest is filler.
      let header = String(decoding: bytes.prefix(256), as: UTF8.self).split(separator: " ")
      let id = header.first { $0.hasPrefix("bench-") }.map(String.init) ?? ""
      let identity = header.first { $0.hasPrefix("nonce:") || $0.hasPrefix("marker:") }.map(String.init) ?? hash
      change { ledger in
        ledger.broadcasts[hash, default: 0] += 1
        if ledger.included[hash] == nil, ledger.identities[identity] == nil {
          ledger.height += 1
          ledger.included[hash] = ledger.height
          ledger.payments[hash] = id
          ledger.identities[identity] = hash
        }
      }
    }

    func mine() {
      change { $0.height += 1 }
    }

    func payments(for id: String) -> [String] {
      reading { $0.payments.filter { $0.value == id }.map(\.key) }
    }

    func broadcasts(of hashHex: String) -> Int {
      reading { $0.broadcasts[hashHex] ?? 0 }
    }

    func confirmations(ofHex hashHex: String) -> UInt64 {
      reading { ledger in
        guard let at = ledger.included[hashHex] else { return 0 }
        return ledger.height - at + 1
      }
    }

    /// The fake chain never reorgs, so a block's hash follows from its height.
    static func blockHash(height: UInt64) -> Data {
      transactionHash(signedTransaction: Data("fake test-chain block \(height)".utf8))
    }

    func blockHash(ofHex hashHex: String) -> Data? {
      reading { $0.included[hashHex] }.map(Self.blockHash(height:))
    }

    func receipt(transactionHash: Data) throws -> Receipt? {
      let hex = Hex.encode(transactionHash)
      guard let height = reading({ $0.included[hex] }) else { return nil }
      return Receipt(status: .success, blockHash: Self.blockHash(height: height), blockHeight: height)
    }

    func pending(transactionHash: Data) throws -> Bool {
      // A broadcast is mined at once: nothing waits.
      false
    }

    func identityUsedBy(identity: Identity) throws -> Data? {
      let word = KillRecoveryBenchmark.identityWord(identity)
      return reading { $0.identities[word] }.flatMap { Hex.decode($0) }
    }

    func effectApplied(intent: PaymentIntent, transactionHash: Data) throws -> Bool {
      let hex = Hex.encode(transactionHash)
      let word = KillRecoveryBenchmark.identityWord(intent.identity)
      return reading { $0.payments[hex] != nil && $0.identities[word] == hex }
    }

    func tipHeight() throws -> UInt64 {
      reading { $0.height }
    }
  }
#endif
