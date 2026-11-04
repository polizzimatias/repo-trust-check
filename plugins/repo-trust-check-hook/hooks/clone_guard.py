#!/usr/bin/env python3
"""
clone_guard.py - Claude Code PreToolUse hook (optional add-on to repo-trust-check).

Claude Code sends the pending Bash/PowerShell tool call as JSON on stdin. If the command
downloads a repo (git clone, gh repo clone, degit, a GitHub archive download) and is not
already going into ~/repo-quarantine, this hook denies it and tells Claude to use the
repo-trust-check skill instead. Everything else is allowed through untouched.

This is a guard rail, not a sandbox: a determined agent can still download code another way.
Turn it off for one session with REPO_TRUST_CHECK_HOOK=off in the environment that starts
Claude Code, or for good with: claude plugin disable repo-trust-check-hook@repo-trust-check
"""
import json, os, re, sys

DOWNLOAD = re.compile(
    r"\bgit(?:\.exe)?\b(?:\s+-{1,2}[\w.-]+(?:[ =]\S+)?)*\s+clone\b"   # git [-c x=y ...] clone
    r"|\bgh(?:\.exe)?\s+repo\s+clone\b"                                 # gh repo clone
    r"|\b(?:npx\s+|pnpm\s+dlx\s+)?(?:degit|tiged)\b"                    # degit / tiged
    r"|\b(?:curl|wget|iwr|Invoke-WebRequest)\b[^\n]*(?:github|gitlab)\.com/[^\s]*(?:/archive/|/zipball|/tarball|/-/archive/)",
    re.I)


def main():
    if os.environ.get("REPO_TRUST_CHECK_HOOK", "").lower() in ("off", "0", "false", "no"):
        return 0
    try:
        event = json.load(sys.stdin)
    except ValueError:
        return 0
    cmd = str((event.get("tool_input") or {}).get("command", ""))
    if not DOWNLOAD.search(cmd) or "repo-quarantine" in cmd or "check_repo.py" in cmd:
        return 0
    reason = ("Blocked by the repo-trust-check hook: code from the internet must be safety-checked "
              "before it is downloaded normally. Use the repo-trust-check skill now: run its "
              "check_repo.py with this repo link. It downloads into ~/repo-quarantine without running "
              "anything, scans it, and you then explain the verdict to the user. If the check already "
              "ran, keep using the copy in the quarantine folder instead of cloning again. If the user "
              "explicitly says this repo is their own or trusted and wants a normal clone, they can turn "
              "this hook off with: claude plugin disable repo-trust-check-hook@repo-trust-check")
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                             "permissionDecision": "deny",
                                             "permissionDecisionReason": reason}}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
