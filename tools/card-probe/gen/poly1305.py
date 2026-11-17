"""Writes polyFast(): Poly1305 over whole 16-byte blocks, unrolled.

Same limb layout as TweetNaCl (17 limbs of 8 bits), with h, r and 320*r kept
in int local variables across blocks, since this card has no RAM int arrays.
Every product sum stays below 2^31. Output goes to stdout.
"""
L = []
L.append("    /** Poly1305 over len bytes of m (whole 16-byte blocks) with r in ph[17..33]; leaves h in ph[0..16]. */")
L.append("    private void polyFast(byte[] m, short off, short len) {")
L.append("        short[] p = ph;")
L.append("        int " + ", ".join(f"r{i} = p[{17+i}]" for i in range(17)) + ";")
L.append("        int " + ", ".join(f"s{i} = 320 * r{i}" for i in range(1, 17)) + ";")
L.append("        int " + ", ".join(f"h{i} = p[{i}]" for i in range(17)) + ";")
L.append("        int u;")
L.append("        int " + ", ".join(f"x{i}" for i in range(17)) + ";")
L.append("        short end = (short) (off + len);")
L.append("        for (short o = off; o < end; o += 16) {")
L.append("            u = 0;")
for j in range(17):
    c = f"(m[(short) (o + {j})] & 0xFF)" if j < 16 else "1"
    L.append(f"            u += h{j} + {c}; h{j} = u & 255; u >>>= 8;")
for i in range(17):
    terms = [f"h{j} * r{i-j}" if j <= i else f"h{j} * s{i+17-j}" for j in range(17)]
    L.append(f"            x{i} = " + " + ".join(terms) + ";")
L.append("            u = 0;")
for j in range(16):
    L.append(f"            u += x{j}; h{j} = u & 255; u >>>= 8;")
L.append("            u += x16; h16 = u & 3; u = 5 * (u >>> 2);")
for j in range(16):
    L.append(f"            u += h{j}; h{j} = u & 255; u >>>= 8;")
L.append("            u += h16; h16 = u;")
L.append("        }")
for i in range(17):
    L.append(f"        p[{i}] = (short) h{i};")
L.append("    }")
print("\n".join(L))
