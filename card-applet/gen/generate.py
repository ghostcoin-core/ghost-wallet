"""Writes the generated Java classes of the applet into src/ghostcard/.

Run with `python3 gen/generate.py`. CI runs it with `--check` and fails when
a generated file differs from what is checked in.
"""
import pathlib
import subprocess
import sys

here = pathlib.Path(__file__).parent
target = here.parent / "src" / "ghostcard"
check = "--check" in sys.argv[1:]
stale = []
for gen, name in (("keccak.py", "KeccakF.java"), ("chacha.py", "ChaCha.java"), ("poly1305.py", "Poly.java")):
    text = subprocess.run([sys.executable, str(here / gen)], check=True, capture_output=True, text=True).stdout
    path = target / name
    if check:
        if not path.exists() or path.read_text() != text:
            stale.append(name)
    else:
        path.write_text(text)
if stale:
    sys.exit("out of date, run python3 gen/generate.py: " + ", ".join(stale))
