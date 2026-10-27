import ExpoModulesCore

/// The feasibility harness as the app sees it: list the registered native
/// benchmarks, run one, and find the results file.
public class GhostBenchModule: Module {
  public func definition() -> ModuleDefinition {
    Name("GhostBench")

    OnCreate {
      BenchRunner.recordUnfinishedRun()
      // A kill-recovery payment left unfinished by a kill is recovered at
      // launch, before anything else runs; the outcome goes into the next
      // kill-recovery run's notes.
      KillRecoveryBenchmark.recoverAtLaunch()
    }

    Function("listBenchmarks") { () -> [String] in
      BenchmarkRegistry.names
    }

    Function("resultsPath") { () -> String in
      ResultsStore.resultsURL.path
    }

    // Runs off the main thread; resolves with the record appended to
    // bench-results.json.
    AsyncFunction("runBenchmark") { (name: String) throws -> [String: Any] in
      let record = try BenchRunner.run(name)
      let data = try JSONEncoder().encode(record)
      return try JSONSerialization.jsonObject(with: data) as? [String: Any] ?? [:]
    }
  }
}
