// The AES-128 operations of the NTAG 424 DNA (CBC without padding, one ECB
// block, CMAC per RFC 4493 / NIST SP 800-38B), the chip's CRC32 of a new
// key, and the system random source. CommonCrypto, so no dependency is added.
// The same operations are mirrored in Node by __tests__/nfc/fake-card.ts and
// checked there against NXP's AN12196 vectors.
import CommonCrypto
import Foundation
import Security

enum CardCryptoError: Error {
  case aes(Int32)
  case random(Int32)
  case length
}

enum CardCrypto {
  static let zeroBlock = Data(count: 16)

  private static func aes(_ operation: CCOperation, key: Data, iv: Data?, data: Data) throws -> Data {
    guard key.count == kCCKeySizeAES128, data.count % kCCBlockSizeAES128 == 0 else {
      throw CardCryptoError.length
    }
    var out = Data(count: data.count + kCCBlockSizeAES128)
    let outCapacity = out.count
    var moved = 0
    let options = CCOptions(iv == nil ? kCCOptionECBMode : 0)
    let vector = iv ?? zeroBlock
    let status = out.withUnsafeMutableBytes { outBytes in
      data.withUnsafeBytes { dataBytes in
        key.withUnsafeBytes { keyBytes in
          vector.withUnsafeBytes { ivBytes in
            CCCrypt(
              operation,
              CCAlgorithm(kCCAlgorithmAES),
              options,
              keyBytes.baseAddress, key.count,
              ivBytes.baseAddress,
              dataBytes.baseAddress, data.count,
              outBytes.baseAddress, outCapacity,
              &moved
            )
          }
        }
      }
    }
    guard status == kCCSuccess else {
      throw CardCryptoError.aes(status)
    }
    return Data(out.prefix(moved))
  }

  static func cbcEncrypt(key: Data, iv: Data, data: Data) throws -> Data {
    try aes(CCOperation(kCCEncrypt), key: key, iv: iv, data: data)
  }

  static func cbcDecrypt(key: Data, iv: Data, data: Data) throws -> Data {
    try aes(CCOperation(kCCDecrypt), key: key, iv: iv, data: data)
  }

  /// One block, AES-ECB.
  static func encryptBlock(key: Data, block: Data) throws -> Data {
    guard block.count == 16 else {
      throw CardCryptoError.length
    }
    return try aes(CCOperation(kCCEncrypt), key: key, iv: nil, data: block)
  }

  private static func shiftLeft(_ block: [UInt8]) -> [UInt8] {
    var out = [UInt8](repeating: 0, count: 16)
    for i in 0..<16 {
      out[i] = (block[i] << 1) | (i < 15 ? block[i + 1] >> 7 : 0)
    }
    if block[0] & 0x80 != 0 {
      out[15] ^= 0x87
    }
    return out
  }

  /// AES-CMAC, 16 bytes.
  static func cmac(key: Data, message: Data) throws -> Data {
    let k1 = shiftLeft([UInt8](try encryptBlock(key: key, block: zeroBlock)))
    let k2 = shiftLeft(k1)
    let bytes = [UInt8](message)
    let blocks = max(1, (bytes.count + 15) / 16)
    let complete = !bytes.isEmpty && bytes.count % 16 == 0
    let lastStart = (blocks - 1) * 16
    var last = [UInt8](repeating: 0, count: 16)
    let tail = Array(bytes[lastStart...])
    for i in 0..<tail.count {
      last[i] = tail[i]
    }
    if complete {
      for i in 0..<16 { last[i] ^= k1[i] }
    } else {
      last[tail.count] = 0x80
      for i in 0..<16 { last[i] ^= k2[i] }
    }
    var state = [UInt8](repeating: 0, count: 16)
    for block in 0..<(blocks - 1) {
      for i in 0..<16 { state[i] ^= bytes[block * 16 + i] }
      state = [UInt8](try encryptBlock(key: key, block: Data(state)))
    }
    for i in 0..<16 { state[i] ^= last[i] }
    return try encryptBlock(key: key, block: Data(state))
  }

  /// ISO/IEC 9797-1 padding method 2.
  static func pad(_ data: Data) -> Data {
    var out = data
    out.append(0x80)
    while out.count % 16 != 0 {
      out.append(0x00)
    }
    return out
  }

  /// The chip's CRC32 of a new key: the IEEE CRC32 without the final inversion, little endian.
  static func crc32NewKey(_ data: Data) -> Data {
    var crc: UInt32 = 0xFFFF_FFFF
    for byte in data {
      crc ^= UInt32(byte)
      for _ in 0..<8 {
        crc = (crc & 1) != 0 ? (crc >> 1) ^ 0xEDB8_8320 : crc >> 1
      }
    }
    return Data([UInt8(crc & 0xFF), UInt8((crc >> 8) & 0xFF), UInt8((crc >> 16) & 0xFF), UInt8((crc >> 24) & 0xFF)])
  }

  static func xor(_ a: Data, _ b: Data) -> Data {
    Data(zip(a, b).map { $0 ^ $1 })
  }

  static func rotateLeft(_ block: Data) -> Data {
    let bytes = [UInt8](block)
    return Data(bytes.dropFirst() + bytes.prefix(1))
  }

  static func constantTimeEqual(_ a: Data, _ b: Data) -> Bool {
    guard a.count == b.count else { return false }
    var difference: UInt8 = 0
    for (x, y) in zip(a, b) {
      difference |= x ^ y
    }
    return difference == 0
  }

  /// `count` bytes from the system random source.
  static func random(_ count: Int) throws -> Data {
    var bytes = Data(count: count)
    let status = bytes.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!) }
    guard status == errSecSuccess else {
      throw CardCryptoError.random(status)
    }
    return bytes
  }

  /// Overwrites `data` with zeros.
  static func wipe(_ data: inout Data) {
    data.resetBytes(in: 0..<data.count)
  }
}
