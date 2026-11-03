#!/usr/bin/env python3
"""
make_demo.py - build the two harmless practice repos with their real file names.

Usage:   python3 make_demo.py [output-folder]      (default: ./demo-output)

The fixtures in examples/ are stored under inert names (dot-claude/, *.sample) so
that no editor or AI tool treats them as live config while they sit in this repo.
This script copies them into the output folder and renames them:
  * a path part "dot-NAME" becomes ".NAME"   (dot-claude -> .claude)
  * a trailing ".sample" is removed          (AGENTS.md.sample -> AGENTS.md)
It also generates the demo's ~1.6 MB "oversized payload" file, which is only
random padding bytes (fixed seed), base64-encoded. It is never decoded or run.

Python 3 standard library only. No network. Runs nothing it creates.
"""
import base64, os, random, shutil, sys

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "examples")
MARKER = ".made-by-make_demo"

BLOB_HEADER = (
    "// HARMLESS DEMO FILE: random padding bytes, base64-encoded. Never decoded or run.\n"
    "// It imitates the size and shape of an oversized hidden payload.\n")


def live_name(part):
    if part.endswith(".sample"):
        part = part[: -len(".sample")]
    if part.startswith("dot-"):
        part = "." + part[len("dot-"):]
    return part


def build(out):
    if os.path.exists(out):
        if os.path.isfile(os.path.join(out, MARKER)):
            shutil.rmtree(out)                       # our own earlier output: rebuild it
        elif os.listdir(out):
            sys.exit(f"Refusing to write into non-empty folder not made by this script: {out}")
    os.makedirs(out, exist_ok=True)
    open(os.path.join(out, MARKER), "w").close()

    for root, _dirs, files in os.walk(SRC):
        for f in files:
            rel = os.path.relpath(os.path.join(root, f), SRC)
            dest = os.path.join(out, *[live_name(p) for p in rel.split(os.sep)])
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            shutil.copyfile(os.path.join(root, f), dest)

    rnd = random.Random(20261026)                    # fixed seed: same file every time
    data = base64.b64encode(bytes(rnd.getrandbits(8) for _ in range(1_200_000))).decode()
    blob = os.path.join(out, "demo-repo", ".github", "setup-cache.js")
    os.makedirs(os.path.dirname(blob), exist_ok=True)
    with open(blob, "w") as fh:
        fh.write(BLOB_HEADER + f'const DATA = "{data}";\nmodule.exports = DATA.length;\n')

    print(f"Built harmless practice repos in {out}:")
    for name in ("demo-repo", "clean-repo"):
        print(f"  {os.path.join(out, name)}")
    print("Now scan them, for example:")
    print(f"  python3 scan_repo.py {os.path.join(out, 'demo-repo')}")
    print(f"  python3 scan_repo.py {os.path.join(out, 'clean-repo')}")


if __name__ == "__main__":
    build(os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "demo-output"))
