"""Writes keccakFast(): Keccak-f[1600] for a Java Card VM with `int` support.

The whole state lives in 50 int local variables (lane L is a{2L} low half and
a{2L+1} high half), so a round touches no array at all. Each round is written
out with constant shifts: theta's column sums and D values, then one output
row at a time: rho and pi into ten locals, chi back into the five lanes that
were just read. Writing in place moves the lanes around; after four rounds
every lane is home again, so the loop body is four rounds and runs six times.

The state is read from the 100-short array `ks` (lane L is ks[4L..4L+3], low
16 bits first) on entry and written back on exit. Output goes to stdout.
"""
ROT = [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14]
PI = [0] * 25
for x in range(5):
    for y in range(5):
        PI[x + 5 * y] = y + 5 * ((2 * x + 3 * y) % 5)
SRC = {PI[i]: i for i in range(25)}


def rot(lo, hi, r):
    """The two halves of a 64-bit left rotation by r of the lane (lo, hi)."""
    if r == 0:
        return lo, hi
    if r == 32:
        return hi, lo
    if r > 32:
        lo, hi, r = hi, lo, r - 32
    return (f"({lo} << {r}) | ({hi} >>> {32 - r})", f"({hi} << {r}) | ({lo} >>> {32 - r})")


def round_(pos, rc):
    """One round. pos[lane] is the local-variable slot that holds the lane."""
    L = []
    for x in range(5):
        for h in range(2):
            L.append(f"c{2*x+h} = " + " ^ ".join(f"a{2*pos[x+5*y]+h}" for y in range(5)) + ";")
    for x in range(5):
        p, n = (x + 4) % 5, (x + 1) % 5
        L.append(f"d{2*x} = c{2*p} ^ ((c{2*n} << 1) | (c{2*n+1} >>> 31));")
        L.append(f"d{2*x+1} = c{2*p+1} ^ ((c{2*n+1} << 1) | (c{2*n} >>> 31));")
    new = list(pos)
    for y in range(5):
        slots = []
        for x in range(5):
            src = SRC[x + 5 * y]
            s = pos[src]
            slots.append(s)
            lo, hi = rot(f"(a{2*s} ^ d{2*(src%5)})", f"(a{2*s+1} ^ d{2*(src%5)+1})", ROT[src])
            L.append(f"b{2*x} = {lo};")
            L.append(f"b{2*x+1} = {hi};")
        # The five results go back into the five slots just read. Each takes
        # the slot in its own column, which is what brings the layout back
        # after four rounds.
        assert sorted(s % 5 for s in slots) == [0, 1, 2, 3, 4]
        for x in range(5):
            s = next(t for t in slots if t % 5 == x)
            new[x + 5 * y] = s
            for h in range(2):
                e = f"b{2*x+h} ^ (~b{2*((x+1)%5)+h} & b{2*((x+2)%5)+h})"
                if x == 0 and y == 0:
                    e += f" ^ ((RCS[(short) ({rc} + {2*h+1})] << 16) | (RCS[(short) ({rc} + {2*h})] & 0xFFFF))"
                L.append(f"a{2*s+h} = {e};")
    assert sorted(new) == list(range(25))
    return L, new


def main():
    out = ["    private void keccakFast() {", "        short[] k = ks;"]
    out.append("        int " + ", ".join(f"a{i}" for i in range(50)) + ";")
    for p in "cdb":
        out.append("        int " + ", ".join(f"{p}{i}" for i in range(10)) + ";")
    for i in range(50):
        out.append(f"        a{i} = (k[{2*i+1}] << 16) | (k[{2*i}] & 0xFFFF);")
    out.append("        for (short r = 0; r < 96; r += 16) {")
    pos = list(range(25))
    for i in range(4):
        lines, pos = round_(pos, "r" if i == 0 else f"r + {4*i}")
        out += ["            " + l for l in lines]
    assert pos == list(range(25)), "the layout must repeat every four rounds"
    out.append("        }")
    for i in range(50):
        out.append(f"        k[{2*i}] = (short) a{i};")
        out.append(f"        k[{2*i+1}] = (short) (a{i} >>> 16);")
    out.append("    }")
    print("\n".join(out))


main()
