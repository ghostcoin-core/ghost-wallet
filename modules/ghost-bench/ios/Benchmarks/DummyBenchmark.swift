import CryptoKit
import Foundation

/// Proves the harness end to end: holds 600 MiB of non-compressible data in
/// RAM, then hashes it with SHA-256 for 30 seconds.
enum DummyBenchmark {
  static let name = "dummy"

  static let allocationBytes = 600 * 1024 * 1024
  static let hashSeconds: Double = 30
  static let chunkBytes = 1024 * 1024

  static func run(_ context: BenchContext) throws {
    let buffer = context.stage("allocate") { () -> UnsafeMutableRawPointer in
      let buffer = UnsafeMutableRawPointer.allocate(byteCount: allocationBytes, alignment: 16)
      // Pseudo-random words so every page is touched and iOS cannot compress
      // the allocation away.
      let words = buffer.bindMemory(to: UInt64.self, capacity: allocationBytes / 8)
      var state: UInt64 = 0x9E37_79B9_7F4A_7C15
      for index in 0..<(allocationBytes / 8) {
        state ^= state << 13
        state ^= state >> 7
        state ^= state << 17
        words[index] = state
      }
      return buffer
    }
    defer { buffer.deallocate() }

    let hashed = context.stage("hash") { () -> Int in
      let deadline = DispatchTime.now().uptimeNanoseconds + UInt64(hashSeconds * 1_000_000_000)
      var hasher = SHA256()
      var offset = 0
      var total = 0
      while DispatchTime.now().uptimeNanoseconds < deadline {
        hasher.update(
          bufferPointer: UnsafeRawBufferPointer(start: buffer + offset, count: chunkBytes))
        total += chunkBytes
        offset = (offset + chunkBytes) % allocationBytes
      }
      let digest = hasher.finalize()
      context.note("digestPrefix", digest.prefix(4).map { String(format: "%02x", $0) }.joined())
      return total
    }

    context.note("allocatedMiB", String(allocationBytes / (1024 * 1024)))
    context.note("hashedMiB", String(hashed / (1024 * 1024)))
  }
}
