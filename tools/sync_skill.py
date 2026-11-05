#!/usr/bin/env python3
"""
sync_skill.py - copy the scanner into the skill folder.

scan_repo.py and iocs.json at the repo root are the single source of truth. The skill
(skills/repo-trust-check/) ships byte-identical copies, because AI tools install a skill
folder on its own and symlinks break on Windows and in some installers.

  python3 tools/sync_skill.py          # copy root files into the skill folder
  python3 tools/sync_skill.py --check  # exit 1 if the copies differ (used by the tests and CI)
"""
import filecmp, os, shutil, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKILL = os.path.join(ROOT, "skills", "repo-trust-check")
FILES = ("scan_repo.py", "iocs.json")


def main():
    check = "--check" in sys.argv[1:]
    stale = [f for f in FILES if not os.path.isfile(os.path.join(SKILL, f))
             or not filecmp.cmp(os.path.join(ROOT, f), os.path.join(SKILL, f), shallow=False)]
    if check:
        for f in stale:
            print(f"OUT OF SYNC: skills/repo-trust-check/{f} differs from ./{f}. Run: python3 tools/sync_skill.py")
        return 1 if stale else 0
    for f in stale:
        shutil.copyfile(os.path.join(ROOT, f), os.path.join(SKILL, f))
        print(f"copied {f} -> skills/repo-trust-check/{f}")
    if not stale:
        print("already in sync")
    return 0


if __name__ == "__main__":
    sys.exit(main())
