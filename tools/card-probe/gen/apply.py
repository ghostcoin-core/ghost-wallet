"""Puts the generated methods into src/ghostprobe/Probe.java.

Each generator prints one method. This replaces the method of the same name in
the applet, from its signature (and the comment line above it, if the
generator prints one) to its closing brace.
"""
import pathlib
import subprocess
import sys

here = pathlib.Path(__file__).parent
target = here.parent / "src" / "ghostprobe" / "Probe.java"
lines = target.read_text().split("\n")
for gen in ("keccak.py", "poly1305.py", "chacha.py"):
    new = subprocess.run([sys.executable, str(here / gen)], check=True, capture_output=True, text=True).stdout.rstrip("\n").split("\n")
    first = next(i for i, l in enumerate(new) if l.startswith("    private "))
    name = new[first].split("(")[0]
    start = next(i for i, l in enumerate(lines) if l.split("(")[0] == name)
    end = next(i for i in range(start, len(lines)) if lines[i] == "    }")
    if first and lines[start - 1].lstrip().startswith("/**"):
        start -= 1
    lines[start:end + 1] = new
target.write_text("\n".join(lines))
