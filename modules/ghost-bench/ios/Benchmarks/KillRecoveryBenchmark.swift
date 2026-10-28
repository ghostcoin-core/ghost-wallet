import Darwin
import Foundation

enum KillRecoveryBenchmarkError: LocalizedError {
  case bindingsMissing
  case noNodeUrl
  case badNodeUrl
  case wrongChain(UInt64)
  case unknownKillPoint(String)
  case notRecovered(String)
  case noSettle

  var errorDescription: String? {
    switch self {
    case .bindingsMissing:
      return "The Swift bindings of the native core (ghost_wallet_core) are not in this build."
    case .noNodeUrl:
      return "No test node is set: put its JSON-RPC URL in the UserDefaults key "
        + "\(TestChainConfig.nodeUrlKey)."
    case .badNodeUrl:
      return "The test node URL in \(TestChainConfig.nodeUrlKey) is not an http or https URL."
    case .wrongChain(let found):
      return "The node is on chain \(found), not the test chain \(KillRecoveryBenchmark.testChain)."
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

/// Survives being killed mid-step: a real send of GHOST on the local test
/// chain (scripts/test-chain.sh), moved through the native payment state
/// machine (prepared, backed up, signed, sent, included, settled), every step
/// saved before its effect. It pays `sendValueWei` from account 0 of the
/// app's public test words to account 3, with the sender's live nonce as its
/// identity. The transaction is a `0x52` account transaction (scheme
/// `0x0003`) signed in the native core with the account's ML-DSA-44 key and
/// fresh randomness from the operating system, and broadcast with
/// eth_sendRawTransaction. The small record is in the Keychain; the signed
/// bytes, about 3.8 KB, are an encrypted payload in protected app storage
/// (KeychainStepStore), written before the record lists them.
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
/// opens every unfinished record off the main thread, asks the native
/// `recover` what to do and does it, until the payment settles: resending
/// only the stored bytes, and only when the chain does not have them, and
/// signing only a payment whose signed bytes were never saved. It then
/// checks on the chain that exactly one transaction from the sender has the
/// payment's nonce, that the sender's nonce count moved by one, that its
/// receipt succeeded in the block the settled record keeps, that its hash is
/// the one it had at the kill, and that the app broadcast it once (counted in
/// the benchmark's saved state: a node cannot tell). The benchmark then
/// removes its own record. The next run writes the table into its notes:
/// `killPoint.<name>` = outcome, `recoveryMs.<name>` and
/// `launchToRecoveredMs.<name>`.
///
/// The test words are Ghost's public counting-bytes test seed, and the
/// funds are test-chain GHOST: each run spends about 0.0002 in fees.
enum KillRecoveryBenchmark {
  static let name = "kill-recovery"
  static let killPointKey = "benchKillPoint"
  static let killSignalKey = "benchKillSignal"

  /// The test chain's identifier (scripts/test-chain.sh).
  static let testChain: UInt64 = 6_777_971
  /// The sending account of the test words, and the recipient's.
  static let senderIndex: UInt32 = 0
  static let recipient = "0xacf1b03442244bc14982f1aae0a11d76e1850e09"
  /// What each run pays: 10^12 wei, a millionth of a GHOST.
  static let sendValueWei: UInt64 = 1_000_000_000_000
  /// The tip of every send, 1 gwei; the fee cap is twice the latest base fee
  /// plus the tip.
  static let priorityFeeWei: UInt64 = 1_000_000_000
  /// How long `wait` sleeps before asking the chain again.
  static let pollSeconds: Double = 1
  /// How many steps a drive takes before it gives up (about ten minutes of
  /// one-second polls).
  static let maxSteps = 600

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

  /// What survives a kill besides the store: the armed kill point, the node,
  /// the app's own count of broadcasts and the outcome table. Written
  /// atomically before every kill and every broadcast.
  struct State: Codable {
    struct Armed: Codable {
      var point: String
      var id: String
      var hashHex: String?
      /// The sender, its nonce and the height a scan starts at: enough to
      /// find the payment on the chain if its record is gone.
      var senderHex: String
      var nonce: UInt64
      var startHeight: UInt64
    }

    var armed: Armed?
    /// The node of the last run, for a recovery at a launch that was not
    /// given one.
    var nodeUrl: String?
    /// eth_sendRawTransaction calls the app made, by transaction hash (hex).
    var broadcasts: [String: Int] = [:]
    var outcomes: [String: String] = [:]
    var recoveryMs: [String: String] = [:]
    var launchToRecoveredMs: [String: String] = [:]
  }

  /// A new file for the real chain: outcomes recorded against the earlier
  /// fake chain never count.
  static var stateURL: URL {
    ResultsStore.documents.appendingPathComponent("kill-recovery-test-chain-state.json")
  }

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

  private static let stateLock = NSLock()

  /// Reads, changes and saves the state in one go.
  static func updateState(_ body: (inout State) -> Void) {
    stateLock.lock()
    defer { stateLock.unlock() }
    var state = loadState()
    body(&state)
    saveState(state)
  }

  /// Held while launch recovery runs; a run waits for it first.
  static let launchRecovery = DispatchGroup()

  /// The node: `benchNodeUrl` if set, else the one the last run used.
  static func nodeURL() throws -> URL {
    let text =
      UserDefaults.standard.string(forKey: TestChainConfig.nodeUrlKey).flatMap { $0.isEmpty ? nil : $0 }
      ?? loadState().nodeUrl
    guard let text = text else { throw KillRecoveryBenchmarkError.noNodeUrl }
    guard let url = URL(string: text), url.scheme == "http" || url.scheme == "https" else {
      throw KillRecoveryBenchmarkError.badNodeUrl
    }
    return url
  }

  static func run(_ context: BenchContext) throws {
    #if GHOST_CORE_BINDINGS
      launchRecovery.wait()
      let url = try nodeURL()
      updateState { $0.nodeUrl = url.absoluteString }
      let node = TestChainView(url: url)
      let chainId = try node.chainId()
      guard chainId == testChain, chainId == testChainId() else {
        throw KillRecoveryBenchmarkError.wrongChain(chainId)
      }
      context.note("chain", "real test chain: \(url.absoluteString), chain id \(chainId)")
      context.note(
        "send",
        "0x52 account transaction, scheme 0x0003, ML-DSA-44 signed in the native core; "
          + "account \(senderIndex) of the test words to \(recipient), \(sendValueWei) wei")
      context.note(
        "store",
        "records: Keychain, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, not synchronizable; "
          + "signed bytes: AES-GCM with a Keychain key, completeFileProtection, atomic writes")
      context.note("payloadBytes", "about 3800")
      let store = KeychainStepStore()

      // Anything launch recovery could not finish (no node at launch, say).
      try context.stage("recover") {
        _ = recoverUnfinished(store: store, node: node, launchStart: nil)
      }
      context.stage("tamper") {
        context.note("tamperedRecord", tamperCheck(store: store))
      }

      let state = loadState()
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
      let intent = try context.stage("prepare") { try sendIntent(node: node) }
      let details = try TestSendDetails.decode(intent.details)
      guard case .accountNonce(let sender, let nonce) = intent.identity else {
        throw KillRecoveryBenchmarkError.notRecovered("the send has no nonce")
      }
      context.note("nonce", String(nonce))
      context.note("startHeight", String(details.startHeight))
      let armed = point.map { point in
        State.Armed(
          point: point.rawValue, id: id, hashHex: nil, senderHex: Hex.encode(sender), nonce: nonce,
          startHeight: details.startHeight)
      }
      updateState { $0.armed = armed }

      let chain = node.scanning(from: details.startHeight)
      try context.stage("payment") {
        let sequence = try PaymentSequence.start(store: store, id: id, intent: intent)
        try kill(at: .prepared, armed: point, sequence: sequence, context: context)
        try drive(sequence, node: chain, kill: point, context: context)
      }

      // Not killed: it settled in this run.
      let outcome = check(id: id, store: store, node: chain, hashAtKill: nil)
      context.note("killPoint.none", outcome)
      updateState { $0.armed = nil }
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
  /// left unfinished, off the main thread (it waits on the chain), and keeps
  /// the outcome for the next run's notes. A run waits for it to end.
  static func recoverAtLaunch() {
    #if GHOST_CORE_BINDINGS
      let launchStart = processStartDate()
      guard let url = try? nodeURL() else { return }
      launchRecovery.enter()
      DispatchQueue.global(qos: .userInitiated).async {
        defer { launchRecovery.leave() }
        _ = recoverUnfinished(
          store: KeychainStepStore(), node: TestChainView(url: url), launchStart: launchStart)
      }
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
    static func recoverUnfinished(store: KeychainStepStore, node: TestChainView, launchStart: Date?) -> Int {
      let start = HeaderSyncBenchmark.uptime()
      let armedAtStart = loadState().armed
      let ids: [String]
      do {
        ids = try store.list()
      } catch {
        if let armed = armedAtStart {
          updateState { $0.outcomes[armed.point] = "error: the records could not be listed: \(error)" }
        }
        return 0
      }

      var found = 0
      for id in ids {
        let armed = armedAtStart?.id == id ? armedAtStart : nil
        let point = armed?.point ?? "external"
        let outcome: String
        do {
          let sequence = try PaymentSequence.open(store: store, id: id)
          if armed == nil, isFinal(sequence.step()) {
            continue
          }
          found += 1
          let details = try TestSendDetails.decode(sequence.record().intent.details)
          let chain = node.scanning(from: details.startHeight)
          try drive(sequence, node: chain, kill: nil, context: nil)
          outcome = check(id: id, store: store, node: chain, hashAtKill: armed?.hashHex)
        } catch {
          found += 1
          outcome = "refused, kept and not sent: \(error)"
        }
        let ms = (HeaderSyncBenchmark.uptime() - start) * 1000
        let launched = launchStart.map { String(format: "%.1f", Date().timeIntervalSince($0) * 1000) }
        updateState { state in
          state.outcomes[point] = outcome
          state.recoveryMs[point] = String(format: "%.1f", ms)
          if let launched = launched {
            state.launchToRecoveredMs[point] = launched
          }
          if armed != nil {
            state.armed = nil
          }
        }
      }

      // Armed, but its record is gone: lost unless the chain has it once.
      if let armed = armedAtStart, !ids.contains(armed.id), let sender = Hex.decode(armed.senderHex) {
        let outcome: String
        do {
          let paid = try node.transactions(from: sender, nonce: armed.nonce, fromHeight: armed.startHeight)
          outcome =
            paid.count == 1
            ? "ok: paid once, record already removed"
            : "FAILED: the record is gone and the chain has \(paid.count) transactions with its nonce"
        } catch {
          outcome = "error: the chain could not be asked: \(error)"
        }
        updateState { state in
          state.outcomes[armed.point] = outcome
          state.armed = nil
        }
      }
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

    /// On the real chain: exactly one transaction from the sender with the
    /// payment's nonce, the sender's nonce count one past it, a successful
    /// receipt, the hash it had at the kill, one broadcast by the app, and
    /// the settled record kept with the receipt's block hash. The
    /// benchmark's own record is then removed; a record that fails the check
    /// is kept to look at.
    static func check(id: String, store: KeychainStepStore, node: TestChainView, hashAtKill: String?) -> String {
      guard let record = try? store.load(id: id) else {
        return "FAILED: the settled record was not kept"
      }
      guard case .accountNonce(let sender, let nonce) = record.intent.identity,
        let details = try? TestSendDetails.decode(record.intent.details)
      else {
        return "FAILED: the record is not a test send"
      }
      do {
        let landed = try node.transactions(from: sender, nonce: nonce, fromHeight: details.startHeight)
        guard landed.count == 1, let hashData = landed.first else {
          return "FAILED: the chain has \(landed.count) transactions from the sender with nonce \(nonce)"
        }
        let hash = Hex.encode(hashData)
        let count = try node.transactionCount(sender, "latest")
        if count != nonce + 1 {
          return "FAILED: the sender's nonce count is \(count), not \(nonce + 1)"
        }
        guard let receipt = try node.receipt(transactionHash: hashData), receipt.status == .success else {
          return "FAILED: no successful receipt"
        }
        if try !node.effectApplied(intent: record.intent, transactionHash: hashData) {
          return "FAILED: the transaction does not pay what the payment says"
        }
        if let before = hashAtKill, before != hash {
          return "FAILED: the transaction hash changed"
        }
        let broadcasts = loadState().broadcasts[hash] ?? 0
        if broadcasts != 1 {
          return "FAILED: broadcast \(broadcasts) times"
        }
        guard record.step == .settled, let inclusion = record.inclusion else {
          return "FAILED: the record is \(record.step), not settled"
        }
        if inclusion.transactionHash != hashData || inclusion.blockHash != receipt.blockHash {
          return "FAILED: the record names another transaction or block"
        }
        try? store.remove(id: id)
        updateState { $0.broadcasts[hash] = nil }
        return "ok: paid once on the test chain, 1 broadcast, same hash, settled record kept"
      } catch {
        return "error: the chain could not be asked: \(error)"
      }
    }

    /// Does what `recover` says until the payment is settled. Only the
    /// stored bytes are ever sent, and only when the chain does not have
    /// them; only a payment with no saved signed bytes is signed.
    static func drive(
      _ sequence: PaymentSequence, node: TestChainView, kill point: KillPoint?, context: BenchContext?
    ) throws {
      for _ in 0..<maxSteps {
        let before = sequence.step()
        let action = try sequence.recover(chain: node)
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
          let signed = try sign(sequence.record().intent, node: node)
          context?.note("payloadBytes", String(signed.envelope.count))
          _ = try sequence.addAttempt(signedTransaction: signed.envelope, validUntil: nil)
          try kill(at: .signed, armed: point, sequence: sequence, context: context)
        case .send:
          let wasSigned = sequence.step() == .signed
          let bytes = try sequence.markSent()
          if wasSigned {
            try kill(at: .sent, armed: point, sequence: sequence, context: context)
          }
          // Counted before it goes out: a kill in between over-counts, never
          // hides a second broadcast.
          let hash = Hex.encode(transactionHash(signedTransaction: bytes))
          updateState { $0.broadcasts[hash, default: 0] += 1 }
          _ = try node.sendRaw(bytes)
          try kill(at: .afterBroadcast, armed: point, sequence: sequence, context: context)
        case .wait:
          Thread.sleep(forTimeInterval: pollSeconds)
        case .done(let step):
          guard step == .settled else {
            throw KillRecoveryBenchmarkError.notRecovered("the payment ended \(step)")
          }
          return
        }
      }
      throw KillRecoveryBenchmarkError.noSettle
    }

    /// Signs the payment's send in the native core with fresh chain data:
    /// the chain id, the genesis hash and the latest base fee. Its nonce is
    /// the payment's identity, never a new one.
    static func sign(_ intent: PaymentIntent, node: TestChainView) throws -> SignedTestSend {
      guard case .accountNonce(let sender, let nonce) = intent.identity else {
        throw KillRecoveryBenchmarkError.notRecovered("the send has no nonce")
      }
      let details = try TestSendDetails.decode(intent.details)
      let chainId = try node.chainId()
      guard chainId == details.chainId, chainId == testChainId() else {
        throw KillRecoveryBenchmarkError.wrongChain(chainId)
      }
      guard let to = Hex.decode(details.recipient), let value = UInt64(details.value) else {
        throw KillRecoveryBenchmarkError.notRecovered("the send's details do not decode")
      }
      let baseFee = try node.baseFee()
      let (doubled, overflow) = baseFee.multipliedReportingOverflow(by: 2)
      guard !overflow, doubled <= UInt64.max - priorityFeeWei else {
        throw KillRecoveryBenchmarkError.notRecovered("the base fee is out of range")
      }
      let send = TestSend(
        chainId: chainId, genesisHash: try node.genesisHash(), nonce: nonce, recipient: to, value: value,
        maxPriorityFeePerGas: priorityFeeWei, maxFeePerGas: doubled + priorityFeeWei,
        gasLimit: testSendGasLimit())
      let signed = try signTestSend(testWords: RestoreBenchmark.testWords, accountIndex: senderIndex, send: send)
      guard signed.sender == sender else {
        throw KillRecoveryBenchmarkError.notRecovered("the signed send is from another account")
      }
      return signed
    }

    /// Ends the process if this is the armed kill point, after saving the
    /// newest attempt's hash and flushing the run's notes.
    static func kill(at here: KillPoint, armed: KillPoint?, sequence: PaymentSequence, context: BenchContext?)
      throws
    {
      guard here == armed, let context = context else { return }
      updateState { state in
        state.armed?.hashHex = sequence.record().attempts.last.map { Hex.encode($0.transactionHash) }
      }
      let signal = UserDefaults.standard.string(forKey: killSignalKey) ?? "sigkill"
      context.note("killedAt", here.rawValue)
      context.note("killedWith", signal == "exit" ? "exit(0)" : "SIGKILL")
      BenchRunner.flushPending()
      if signal == "exit" {
        exit(0)
      }
      Darwin.kill(getpid(), SIGKILL)
    }

    /// A send of `sendValueWei` from account 0 of the test words to account
    /// 3, with the sender's pending nonce count as its nonce and the tip as
    /// the height a scan for it starts at.
    static func sendIntent(node: TestChainView) throws -> PaymentIntent {
      let sender = try senderAddress()
      let startHeight = try node.blockNumber()
      let nonce = try node.transactionCount(sender, "pending")
      let details = TestSendDetails(
        recipient: recipient, value: String(sendValueWei), startHeight: startHeight, chainId: testChain)
      return PaymentIntent(
        kind: .send, identity: .accountNonce(account: sender, nonce: nonce), details: details.encoded())
    }

    /// The 20-byte address of the sending account of the test words.
    static func senderAddress() throws -> Data {
      let text = try testSendSender(testWords: RestoreBenchmark.testWords, accountIndex: senderIndex)
      guard let sender = Hex.decode(text), sender.count == 20 else {
        throw KillRecoveryBenchmarkError.notRecovered("the sender's address does not decode")
      }
      return sender
    }

    /// Saves a damaged record and checks it is refused, then removes it. Its
    /// intent is a test send that is never signed or sent.
    static func tamperCheck(store: KeychainStepStore) -> String {
      let id = "bench-tamper-check"
      defer { try? store.remove(id: id) }
      do {
        try? store.remove(id: id)
        let details = TestSendDetails(
          recipient: recipient, value: String(sendValueWei), startHeight: 0, chainId: testChain)
        let intent = PaymentIntent(
          kind: .send, identity: .accountNonce(account: try senderAddress(), nonce: 0), details: details.encoded())
        let sequence = try PaymentSequence.start(store: store, id: id, intent: intent)
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
