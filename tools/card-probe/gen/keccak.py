"""Writes keccakFast(): Keccak-f[1600] unrolled for a 16-bit Java Card VM.

Each lane is four 16-bit limbs (limb 0 is the low 16 bits). Every round is
written out with constant indexes: theta's column sums and D values in local
variables, rho and pi read straight into the 20 locals of one output plane,
then chi writes that plane to the other state array. Two rounds per loop pass
swap the arrays, so no copy is needed. Output goes to stdout.
"""
ROT = [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14]
PI = [0] * 25
for x in range(5):
    for y in range(5):
        PI[x + 5 * y] = y + 5 * ((2 * x + 3 * y) % 5)
SRC = {PI[i]: i for i in range(25)}


def half(A, E, rcoff):
    L = []
    for x in range(5):
        for k in range(4):
            i = x * 4 + k
            L.append(f"c{i} = (short) ({A}[{i}] ^ {A}[{i+20}] ^ {A}[{i+40}] ^ {A}[{i+60}] ^ {A}[{i+80}]);")
    for x in range(5):
        p = (x + 4) % 5
        n = (x + 1) % 5
        for k in range(4):
            L.append(f"d{x*4+k} = (short) (c{p*4+k} ^ (short) (c{n*4+k} << 1) ^ (short) ((c{n*4+(k-1)%4} >> 15) & 1));")
    for y in range(5):
        for x in range(5):
            dst = x + 5 * y
            src = SRC[dst]
            sx = src % 5
            r = ROT[src]
            q = r >> 4
            s = r & 15
            for k in range(4):
                L.append(f"w{k} = (short) ({A}[{src*4+k}] ^ d{sx*4+k});")
            for k in range(4):
                a = (k - q) % 4
                b = (k - q - 1) % 4
                if s == 0:
                    L.append(f"b{x*4+k} = w{a};")
                else:
                    L.append(f"b{x*4+k} = (short) ((short) (w{a} << {s}) | (short) ((short) (w{b} >> {16-s}) & {(1<<s)-1}));")
        for x in range(5):
            for k in range(4):
                o = (x + 5 * y) * 4 + k
                e = f"(short) (b{x*4+k} ^ (short) (~b{((x+1)%5)*4+k} & b{((x+2)%5)*4+k}))"
                if y == 0 and x == 0:
                    e = f"(short) ({e} ^ RCS[(short) ({rcoff} + {k})])"
                L.append(f"{E}[{o}] = {e};")
    return L


decl = ["short " + ", ".join(f"{p}{i}" for i in range(20)) + ";" for p in "cdb"] + ["short w0, w1, w2, w3;"]
body = ["    private void keccakFast() {", "        short[] a = ks;", "        short[] e = kf;"] + ["        " + d for d in decl]
body += ["        for (short r = 0; r < 96; r += 8) {"]
body += ["            " + l for l in half("a", "e", "r")]
body += ["            " + l for l in half("e", "a", "(short) (r + 4)")]
body += ["        }", "    }"]
print("\n".join(body))
