"""Writes polyFast(): Poly1305 over whole 16-byte blocks, unrolled.

Ten 13-bit limbs, as in poly1305-donna's 16-bit version: 100 multiplications
per block. h, r and 5*r stay in int local variables across blocks, since this
card has no RAM int arrays. Sums are unsigned 32-bit values: each limb's sum
is carried after five products so it stays below 2^32, and every shift is
`>>>`. r is read from ph[17..32] (bytes, already clamped) and h is left in
ph[0..16] as 8-bit limbs for polyFinish(). Output goes to stdout.
"""


def limb(i, word):
    """Bits 13i..13i+12 of a 128-bit value given as 16-bit words word(0..7)."""
    w, sh = divmod(13 * i, 16)
    e = word(w) if sh == 0 else f"({word(w)} >>> {sh})"
    if sh > 3 and w + 1 < 8:
        e = f"({e} | ({word(w + 1)} << {16 - sh}))"
    return f"{e} & 0x1FFF"


def term(i, j):
    return f"h{j} * r{i-j}" if j <= i else f"h{j} * s{i+10-j}"


L = []
L.append("    /** Poly1305 over len bytes of m (whole 16-byte blocks) with r in ph[17..32]; leaves h in ph[0..16]. */")
L.append("    private void polyFast(byte[] m, short off, short len) {")
L.append("        short[] p = ph;")
L.append("        int " + ", ".join(f"t{i} = p[{17+2*i}] | (p[{18+2*i}] << 8)" for i in range(8)) + ";")
L.append("        int " + ", ".join(f"r{i} = {limb(i, lambda w: f't{w}')}" for i in range(10)) + ";")
L.append("        int " + ", ".join(f"s{i} = 5 * r{i}" for i in range(1, 10)) + ";")
L.append("        int " + ", ".join(f"h{i} = 0" for i in range(10)) + ";")
L.append("        int " + ", ".join(f"x{i}" for i in range(10)) + ";")
L.append("        int u;")
L.append("        short end = (short) (off + len);")
L.append("        for (short o = off; o < end; o += 16) {")
for i in range(8):
    L.append(f"            t{i} = (m[(short) (o + {2*i})] & 0xFF) | ((m[(short) (o + {2*i+1})] & 0xFF) << 8);")
for i in range(10):
    hi = " + 0x800" if i == 9 else ""
    L.append(f"            h{i} += ({limb(i, lambda w: f't{w}')}){hi};")
L.append("            u = 0;")
for i in range(10):
    L.append(f"            x{i} = u + " + " + ".join(term(i, j) for j in range(5)) + ";")
    L.append(f"            u = x{i} >>> 13;")
    L.append(f"            x{i} = (x{i} & 0x1FFF) + " + " + ".join(term(i, j) for j in range(5, 10)) + ";")
    L.append(f"            u += x{i} >>> 13;")
L.append("            u = 5 * u + (x0 & 0x1FFF);")
L.append("            h0 = u & 0x1FFF;")
L.append("            h1 = (x1 & 0x1FFF) + (u >>> 13);")
for i in range(2, 10):
    L.append(f"            h{i} = x{i} & 0x1FFF;")
L.append("        }")
# Carry fully, then repack the 13-bit limbs as bytes.
L.append("        u = h1 >>> 13; h1 &= 0x1FFF;")
for i in range(2, 10):
    L.append(f"        u += h{i}; h{i} = u & 0x1FFF; u >>>= 13;")
L.append("        u = 5 * u + h0; h0 = u & 0x1FFF; h1 += u >>> 13;")
L.append("        u = 0;")
bits = 0
byte = 0
for i in range(10):
    L.append(f"        u += h{i}{' << ' + str(bits) if bits else ''};")
    bits += 13
    while bits >= 8 and byte < 16:
        L.append(f"        p[{byte}] = (short) (u & 255); u >>>= 8;")
        byte += 1
        bits -= 8
L.append("        p[16] = (short) u;")
L.append("    }")
print("\n".join(L))
