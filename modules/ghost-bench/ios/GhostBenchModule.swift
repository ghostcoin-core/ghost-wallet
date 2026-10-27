import ExpoModulesCore

/// The feasibility harness as the app sees it: list the registered native
/// benchmarks, run one, and find the results file.
public class GhostBenchModule: Module {
  public func definition() -> ModuleDefinition {
    Name("GhostBench")

    OnCreate {
      BenchRunner.recordUnfinishedRun()
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
