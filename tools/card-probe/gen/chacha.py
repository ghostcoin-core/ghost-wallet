"""Writes chachaFast(): one ChaCha20 block, XORed straight into a byte array.

The 16 words stay in int local variables and every rotation is written inline,
so the 20 rounds make no method call. The key stream is XORed into
out[off..off+len), where len is 64 or 32, without passing through a block
buffer. The probe's key is bytes 00..1f and its nonce bytes 00..0b. Output
goes to stdout.
"""
K = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574] + [
    sum((4 * i + b) << (8 * b) for b in range(4)) for i in range(8)] + [None, 0x03020100, 0x07060504, 0x0b0a0908]


def qr(a, b, c, d):
    out = []
    for x, y, z, n in ((a, b, d, 16), (c, d, b, 12), (a, b, d, 8), (c, d, b, 7)):
        out.append(f"x{x} += x{y}; x{z} ^= x{x}; x{z} = (x{z} << {n}) | (x{z} >>> {32 - n});")
    return out


L = []
L.append("    /** XORs one ChaCha20 key-stream block into out[off..off+len); len is 64 or 32. */")
L.append("    private static void chachaFast(int counter, byte[] out, short off, short len) {")
L.append("        int " + ", ".join(f"x{i} = " + ("counter" if K[i] is None else f"0x{K[i]:08x}") for i in range(16)) + ";")
L.append("        for (short r = 0; r < 10; r++) {")
for q in ((0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15),
          (0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14)):
    L += ["            " + l for l in qr(*q)]
L.append("        }")
for i in range(16):
    if i == 8:
        L.append("        if (len == 32) {")
        L.append("            return;")
        L.append("        }")
    L.append(f"        x{i} += " + ("counter" if K[i] is None else f"0x{K[i]:08x}") + ";")
    for b in range(4):
        v = f"x{i}" if b == 0 else f"(x{i} >>> {8*b})"
        L.append(f"        out[off++] ^= (byte) {v};")
L.append("    }")
print("\n".join(L))
