#!/usr/bin/env python3
"""
check_repo.py - download a repo into a quarantine folder WITHOUT running anything,
then scan it with scan_repo.py (which sits next to this file).

Usage:
  python3 check_repo.py <repo URL>          # clone into ~/repo-quarantine/<name>, then scan
  python3 check_repo.py <existing folder>   # scan a folder that is already on disk, in place

Options:
  --quarantine DIR   use DIR instead of ~/repo-quarantine (or set REPO_QUARANTINE_DIR)

What it does:
  1. git clone with repo hooks off, no submodules, no Git LFS downloads, symlinks
     written as plain files, and no password prompts.
  2. python3 scan_repo.py <folder> --out <quarantine>/<name>.scan-report.md
     (read-only, offline, standard library only).
  3. Prints the report and a last line: RESULT: <verdict> | folder: ... | report: ...

It never runs, installs or opens anything from the downloaded repo.
Exit codes: 0 looks clean, 1 review, 2 do not open, 3 could not download or scan.

MIT License. Copyright 2026 Matias Polizzi. https://github.com/polizzimatias/repo-trust-check
"""
import os, re, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
SCANNER = os.path.join(HERE, "scan_repo.py")
VERDICTS = {0: "Looks clean", 1: "Review before opening", 2: "Do not open"}
REMOTE = re.compile(r"^(https?|ssh|git|file)://[^\s]+$|^[\w.-]+@[\w.-]+:[^\s]+$", re.I)


def fail(msg):
    print(f"ERROR: {msg}")
    print("RESULT: Could not check | Nothing was run.")
    sys.exit(3)


def normalize(url):
    """Turn a GitHub/GitLab page link (.../tree/main/x, .../blob/...) into the repo's clone URL."""
    url = url.strip().strip("<>\"'")
    m = re.match(r"^(https?://(?:www\.)?(?:github\.com|codeberg\.org|bitbucket\.org)/[^/\s]+/[^/\s#?]+)", url, re.I)
    if m:
        return m.group(1)
    m = re.match(r"^(https?://gitlab\.com/.+?)(?:/-/.*)?$", url, re.I)  # GitLab: group/sub/repo/-/tree/...
    if m:
        return m.group(1)
    return url


def repo_name(url):
    base = re.split(r"[/:]", url.rstrip("/"))[-1]
    base = re.sub(r"\.git$", "", base, flags=re.I)
    base = re.sub(r"[^A-Za-z0-9._-]", "-", base).strip(".-")
    return base or "repo"


def free_path(root, name):
    path, n = os.path.join(root, name), 2
    while os.path.exists(path) or os.path.exists(path + ".scan-report.md"):
        path, n = os.path.join(root, f"{name}-{n}"), n + 1
    return path


def safe_clone(url, dest):
    null = os.devnull  # /dev/null, or NUL on Windows
    safe = ["-c", f"core.hooksPath={null}", "-c", "core.symlinks=false", "-c", "core.fsmonitor=false"]
    cmd = (["git", "-c", "protocol.ext.allow=never"] + safe[:2] +
           ["clone", "--no-recurse-submodules"] + safe + ["--", url, dest])
    env = dict(os.environ, GIT_LFS_SKIP_SMUDGE="1", GIT_TERMINAL_PROMPT="0")
    print("Downloading (nothing from the repo is run):")
    print("  GIT_LFS_SKIP_SMUDGE=1 git clone --no-recurse-submodules -c core.hooksPath=%s "
          "-c core.symlinks=false %s %s" % (null, url, dest))
    try:
        r = subprocess.run(cmd, env=env, stdin=subprocess.DEVNULL, timeout=900)
    except FileNotFoundError:
        fail("git is not installed, so the repo could not be downloaded safely.")
    except subprocess.TimeoutExpired:
        fail("the download took longer than 15 minutes and was stopped.")
    if r.returncode != 0:
        fail("git could not download this link (wrong URL, private repo, or no internet).")


def main():
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except AttributeError:
        pass
    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help"):
        print(__doc__)
        sys.exit(0)
    root = os.environ.get("REPO_QUARANTINE_DIR") or os.path.join(os.path.expanduser("~"), "repo-quarantine")
    if "--quarantine" in args:
        i = args.index("--quarantine")
        if i + 1 >= len(args):
            fail("--quarantine needs a folder")
        root = args[i + 1]
        del args[i:i + 2]
    if len(args) != 1:
        fail("give exactly one repo link or folder")
    target = args[0]
    if not os.path.isfile(SCANNER):
        fail(f"scan_repo.py is missing next to {__file__}")
    root = os.path.abspath(os.path.expanduser(root))

    if os.path.isdir(target):                       # already on disk: scan in place, move nothing
        folder = os.path.abspath(target)
        report = folder.rstrip(os.sep) + ".scan-report.md"
        if not os.access(os.path.dirname(report) or ".", os.W_OK):
            os.makedirs(root, exist_ok=True)
            report = os.path.join(root, os.path.basename(folder) + ".scan-report.md")
        print(f"Scanning the folder where it is (nothing is moved or run): {folder}")
    else:
        url = normalize(target)
        if url.startswith("-") or "::" in url or not REMOTE.match(url):
            fail(f"this does not look like a repo link: {target!r}")
        os.makedirs(root, exist_ok=True)
        folder = free_path(root, repo_name(url))
        report = folder + ".scan-report.md"
        safe_clone(url, folder)

    print(f"Scanning {folder} (read-only, offline)...\n")
    r = subprocess.run([sys.executable, SCANNER, folder, "--out", report], cwd=root if os.path.isdir(root) else None,
                       stdin=subprocess.DEVNULL)
    if r.returncode not in VERDICTS:
        fail("the scanner did not finish.")
    print(f"RESULT: {VERDICTS[r.returncode]} | folder: {folder} | report: {report}")
    sys.exit(r.returncode)


if __name__ == "__main__":
    main()
