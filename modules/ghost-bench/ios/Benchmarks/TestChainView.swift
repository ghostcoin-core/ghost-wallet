import Foundation

#if GHOST_CORE_BINDINGS
  /// What a test send pays, kept as JSON in the payment intent's details:
  /// enough to rebuild it and to check its effect on the chain. Public chain
  /// data only.
  struct TestSendDetails: Codable {
    /// The recipient, "0x" and 40 hex digits.
    var recipient: String
    /// The amount in wei, in decimal.
    var value: String
    /// The node's tip when the payment was prepared: no block below it can
    /// hold the send, so a nonce scan starts here.
    var startHeight: UInt64
    var chainId: UInt64

    static func decode(_ data: Data) throws -> TestSendDetails {
      do {
        return try JSONDecoder().decode(TestSendDetails.self, from: data)
      } catch {
        throw StepError.Chain(reason: "the payment's details are not a test send")
      }
    }

    func encoded() -> Data {
      (try? JSONEncoder().encode(self)) ?? Data()
    }
  }

  /// How a node answered eth_sendRawTransaction.
  enum BroadcastAnswer {
    /// Taken, and its hash is keccak256 of the bytes.
    case sent
    /// The node has these bytes already.
    case alreadyKnown
    /// The node has a transaction with this nonce in a block already: the
    /// next `recover` reads which one.
    case nonceUsed
  }

  /// The real test chain as the payment state machine sees it: JSON-RPC to
  /// the node of scripts/test-chain.sh (URL from `benchNodeUrl`, timeout
  /// `TestChainConfig.requestTimeoutSeconds`). Every call waits for its
  /// answer; the core calls it off the main thread.
  ///
  /// The node shows a `0x52` account transaction as a type `0x02` one
  /// without `v`, `r` and `s`, plus `scheme`, `publicKey` and `signature`:
  /// only the fields needed here are read, the rest is ignored. A failure is
  /// a `StepError.Chain`, so the state machine never acts on a guess.
  final class TestChainView: ChainView {
    let url: URL
    /// Where a scan for the transaction that used a nonce starts.
    let scanFrom: UInt64
    private let session: URLSession

    init(url: URL, scanFrom: UInt64 = 0) {
      self.url = url
      self.scanFrom = scanFrom
      let configuration = URLSessionConfiguration.ephemeral
      configuration.timeoutIntervalForRequest = TestChainConfig.requestTimeoutSeconds
      session = URLSession(configuration: configuration)
    }

    /// The same node, scanning from another height.
    func scanning(from height: UInt64) -> TestChainView {
      TestChainView(url: url, scanFrom: height)
    }

    // MARK: ChainView

    func receipt(transactionHash: Data) throws -> Receipt? {
      try chainErrors {
        let hash = "0x" + Hex.encode(transactionHash)
        guard let receipt = try object("eth_getTransactionReceipt", [hash]) else {
          return nil
        }
        guard let status = receipt["status"] as? String, let code = Hex.quantity(status) else {
          throw StepError.Chain(reason: "a receipt has no status")
        }
        guard let heightText = receipt["blockNumber"] as? String, let height = Hex.quantity(heightText) else {
          throw StepError.Chain(reason: "a receipt has no block number")
        }
        let blockHash = try Self.hash32(receipt["blockHash"], "receipt block")
        return Receipt(status: code == 1 ? .success : .failed, blockHash: blockHash, blockHeight: height)
      }
    }

    func pending(transactionHash: Data) throws -> Bool {
      try chainErrors {
        // Held by the node: in its pool (no block number yet), or mined since
        // the receipt was read, which the next pass sees. Either way it must
        // not be sent again.
        try object("eth_getTransactionByHash", ["0x" + Hex.encode(transactionHash)]) != nil
      }
    }

    func identityUsedBy(identity: Identity) throws -> Data? {
      try chainErrors {
        guard case .accountNonce(let account, let nonce) = identity else { return nil }
        guard try transactionCount(account, "latest") > nonce else { return nil }
        let found = try transactions(from: account, nonce: nonce, fromHeight: scanFrom)
        guard let first = found.first else {
          throw StepError.Chain(
            reason: "the nonce is used, but no block from height \(scanFrom) holds a transaction with it")
        }
        return first
      }
    }

    func effectApplied(intent: PaymentIntent, transactionHash: Data) throws -> Bool {
      try chainErrors {
        guard case .accountNonce(let account, let nonce) = intent.identity else { return false }
        let details = try TestSendDetails.decode(intent.details)
        guard try receipt(transactionHash: transactionHash)?.status == .success,
          let tx = try object("eth_getTransactionByHash", ["0x" + Hex.encode(transactionHash)])
        else { return false }
        guard let from = (tx["from"] as? String).flatMap({ Hex.decode($0) }),
          let to = (tx["to"] as? String).flatMap({ Hex.decode($0) }),
          let valueText = tx["value"] as? String, let value = Hex.quantity(valueText),
          let nonceText = tx["nonce"] as? String, let txNonce = Hex.quantity(nonceText)
        else { return false }
        return from == account && txNonce == nonce && to == Hex.decode(details.recipient)
          && String(value) == details.value
      }
    }

    func tipHeight() throws -> UInt64 {
      try chainErrors { try blockNumber() }
    }

    // MARK: The node

    /// eth_chainId.
    func chainId() throws -> UInt64 {
      try quantity(try call("eth_chainId", []), "eth_chainId")
    }

    /// eth_blockNumber.
    func blockNumber() throws -> UInt64 {
      try quantity(try call("eth_blockNumber", []), "eth_blockNumber")
    }

    /// The hash of block 0.
    func genesisHash() throws -> Data {
      guard let block = try object("eth_getBlockByNumber", ["0x0", false]) else {
        throw StepError.Chain(reason: "the node has no block 0")
      }
      return try Self.hash32(block["hash"], "block 0")
    }

    /// The latest block's baseFeePerGas.
    func baseFee() throws -> UInt64 {
      guard let block = try object("eth_getBlockByNumber", ["latest", false]) else {
        throw StepError.Chain(reason: "the node has no latest block")
      }
      return try quantity(block["baseFeePerGas"] ?? NSNull(), "baseFeePerGas")
    }

    /// eth_getTransactionCount(account, tag).
    func transactionCount(_ account: Data, _ tag: String) throws -> UInt64 {
      try quantity(try call("eth_getTransactionCount", ["0x" + Hex.encode(account), tag]), "a nonce count")
    }

    /// The hashes of every transaction in a block from `account` with
    /// `nonce`, from `height` to the tip.
    func transactions(from account: Data, nonce: UInt64, fromHeight height: UInt64) throws -> [Data] {
      let tip = try blockNumber()
      var found: [Data] = []
      var start = height
      while start <= tip {
        let last = min(tip, start + 19)
        let blocks = try batch(
          (start...last).map { ("eth_getBlockByNumber", ["0x" + String($0, radix: 16), true] as [Any]) })
        for case let block as [String: Any] in blocks {
          for case let tx as [String: Any] in block["transactions"] as? [Any] ?? [] {
            guard let from = (tx["from"] as? String).flatMap({ Hex.decode($0) }), from == account,
              let nonceText = tx["nonce"] as? String, Hex.quantity(nonceText) == nonce
            else { continue }
            found.append(try Self.hash32(tx["hash"], "transaction"))
          }
        }
        start = last + 1
      }
      return found
    }

    /// eth_sendRawTransaction of `bytes`. The node's hash must be
    /// keccak256 of the bytes.
    func sendRaw(_ bytes: Data) throws -> BroadcastAnswer {
      let hash = transactionHash(signedTransaction: bytes)
      do {
        let result = try call("eth_sendRawTransaction", ["0x" + Hex.encode(bytes)])
        guard try Self.hash32(result, "eth_sendRawTransaction") == hash else {
          throw StepError.Chain(reason: "the node's transaction hash is not keccak256 of the bytes")
        }
        return .sent
      } catch NodeRefusal.message(let message) {
        let lower = message.lowercased()
        if lower.contains("already known") {
          return .alreadyKnown
        }
        if lower.contains("nonce too low") {
          return .nonceUsed
        }
        throw StepError.Chain(reason: "the node refused the send: \(message)")
      }
    }

    // MARK: JSON-RPC

    /// A JSON-RPC error object's message.
    private enum NodeRefusal: Error {
      case message(String)
    }

    private func chainErrors<T>(_ body: () throws -> T) throws -> T {
      do {
        return try body()
      } catch let error as StepError {
        throw error
      } catch NodeRefusal.message(let message) {
        throw StepError.Chain(reason: message)
      } catch {
        throw StepError.Chain(reason: error.localizedDescription)
      }
    }

    /// One call's result object, or nil for a JSON null.
    private func object(_ method: String, _ params: [Any]) throws -> [String: Any]? {
      let result = try call(method, params)
      if result is NSNull {
        return nil
      }
      guard let object = result as? [String: Any] else {
        throw StepError.Chain(reason: "\(method) did not return an object")
      }
      return object
    }

    private func quantity(_ result: Any, _ name: String) throws -> UInt64 {
      guard let text = result as? String, let value = Hex.quantity(text) else {
        throw StepError.Chain(reason: "\(name) is not a hex quantity")
      }
      return value
    }

    private static func hash32(_ value: Any?, _ name: String) throws -> Data {
      guard let text = value as? String, let hash = Hex.decode(text), hash.count == 32 else {
        throw StepError.Chain(reason: "the \(name) has no 32-byte hash")
      }
      return hash
    }

    private func call(_ method: String, _ params: [Any]) throws -> Any {
      let body: [String: Any] = ["jsonrpc": "2.0", "id": 1, "method": method, "params": params]
      guard let answer = try post(body) as? [String: Any] else {
        throw StepError.Chain(reason: "\(method) did not return a JSON-RPC answer")
      }
      return try Self.result(of: answer, method)
    }

    /// One JSON-RPC batch; the results in the order of `calls`.
    private func batch(_ calls: [(String, [Any])]) throws -> [Any] {
      let body: [[String: Any]] = calls.enumerated().map { index, call in
        ["jsonrpc": "2.0", "id": index, "method": call.0, "params": call.1]
      }
      guard let answers = try post(body) as? [Any] else {
        throw StepError.Chain(reason: "the node did not answer a JSON-RPC batch")
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
          throw StepError.Chain(reason: "no answer to \(calls[index].0)")
        }
        return try Self.result(of: answer, calls[index].0)
      }
    }

    private static func result(of answer: [String: Any], _ method: String) throws -> Any {
      if let error = answer["error"] as? [String: Any] {
        throw NodeRefusal.message(error["message"] as? String ?? "\(method) failed")
      }
      guard let result = answer["result"] else {
        throw StepError.Chain(reason: "an answer to \(method) has no result")
      }
      return result
    }

    private func post(_ body: Any) throws -> Any {
      var request = URLRequest(url: url)
      request.httpMethod = "POST"
      request.setValue("application/json", forHTTPHeaderField: "Content-Type")
      request.httpBody = try JSONSerialization.data(withJSONObject: body)

      let done = DispatchSemaphore(value: 0)
      var outcome: Result<Data, Error> = .failure(StepError.Chain(reason: "the node did not answer"))
      let task = session.dataTask(with: request) { data, response, error in
        if let error = error {
          outcome = .failure(StepError.Chain(reason: error.localizedDescription))
        } else if let http = response as? HTTPURLResponse, !(200..<300).contains(http.statusCode) {
          outcome = .failure(StepError.Chain(reason: "HTTP status \(http.statusCode)"))
        } else {
          outcome = .success(data ?? Data())
        }
        done.signal()
      }
      task.resume()
      done.wait()
      let data = try outcome.get()
      guard let answer = try? JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed]) else {
        throw StepError.Chain(reason: "the node's answer is not JSON")
      }
      return answer
    }
  }
#endif
