# Check a repo before you open it in an AI coding tool - 5 steps

1. **Make a safe folder.** `mkdir ~/repo-check && cd ~/repo-check`.
   Put `scan_repo.py` (and optionally `iocs.json`) from
   https://github.com/polizzimatias/repo-trust-check in it.
   This folder is *not* the project - it's your workbench.
2. **Download the repo without running it.**
   `GIT_LFS_SKIP_SMUDGE=1 git clone --no-recurse-submodules -c core.hooksPath=/dev/null -c core.symlinks=false https://github.com/OWNER/REPO.git target`
   (or Download ZIP and unzip into `target`). Do **not** open `target` in
   Claude Code, Cursor, Codex, Gemini CLI or VS Code yet, and do **not** run
   `npm install`.
3. **Scan it.** `python3 scan_repo.py target`. It only reads files; it runs
   nothing from the repo and makes no network calls.
4. **Read the verdict** at the bottom (also saved as `scan-report.md`):
   - **Looks clean** - no auto-run hooks or hidden payloads found.
   - **Review before opening** - read each MEDIUM item; most are normal
     project setup, but confirm you recognise them.
   - **Do not open** - something would run automatically or matches known
     attack signs. Don't open it; tell the repo owner or report it to GitHub.
5. **Open it carefully.** Even when clean, open it in VS Code/Cursor with
   **Restricted Mode** first ("Don't trust" when asked about workspace trust),
   and install dependencies with `npm install --ignore-scripts`.

Practice first: `python3 make_demo.py`, then
`python3 scan_repo.py demo-output/demo-repo` (should say **Do not open**) and
`python3 scan_repo.py demo-output/clean-repo` (should say **Looks clean**).

Optional: paste the prompt in [PROMPT.md](PROMPT.md) into Claude Code or Codex (started in
`~/repo-check`, never inside `target`) and let it do steps 2-4 for you.

---

## Caveats - please read

- **It's a heuristic, not antivirus.** It looks for *patterns* (hooks,
  auto-run tasks, install scripts, big encoded files, odd URLs). Expect
  **false positives** (normal projects often have MEDIUM items such as a
  `postinstall` or a `CLAUDE.md` that tells the agent to run tests) and
  **false negatives** (a careful attacker can write something it misses).
  "Looks clean" is not a guarantee.
- **Never run untrusted code to "check" it.** No `npm install`, no
  `make`, no "just open it and see". Reading is safe; running is not.
- **It checks one snapshot.** JFrog found the attacker kept clean-looking
  default branches and put the publisher on short-lived `chore/ci-*` branches.
  The scanner flags those branch names in history if you cloned with git, but
  only scans the files of the branch you checked out.
- **AI agents read files you didn't ask them to.** Claude Code can pick up a
  `CLAUDE.md` in a subfolder when it reads files there, so the prompt tells the
  agent to treat repo content as untrusted data and rely on the report.
- **Known indicators are optional extras.** `iocs.json` is copied from
  JFrog's report (package names, file names, hashes, the address
  `43[.]228[.]157[.]68` and the domain `aiarmor[.]website`, written "defanged"
  here so they can't be clicked). New campaigns will use new ones; the generic
  checks are the main defense.

## If something HIGH shows up in a repo you ALREADY opened

Follow JFrog's own remediation guidance
(https://research.jfrog.com/post/beyond-testmetest-42-hijacked-github-repos/,
26 Oct 2026). The ordering point below is about the campaign's **npm worm**
(the malicious package versions you may have installed), and it matters
before you touch any token. In their words:

> "Remove `net-health-checker` and `pkg-runtime` persistence, including their
> LaunchAgents, systemd user services and associated files, before revoking
> the stolen GitHub token because the npm worm contains a token-revocation
> wiper."

They list the persistence paths as `~/.local/bin/net-health-checker.sh`,
`~/.config/net-health-checker/`, `~/.local/share/runtimes/sync.py` and
`/var/tmp/.fontconfig_state`. So: remove the persistence first, then
revoke tokens. After that, JFrog says to revoke and rotate
GitHub, GitLab, npm, PyPI, RubyGems, cloud, SSH, Vault, Kubernetes and
AI-provider credentials, treat installation of a full-worm version as a host
compromise, and rebuild affected systems from trusted sources. If this is a
work computer, contact your IT/security team first.

## Free, well-known tools that complement this

| Tool | What it adds | Official link |
|---|---|---|
| Gitleaks | Finds leaked secrets in files and git history | https://github.com/gitleaks/gitleaks |
| Semgrep | Pattern/code scanning with community rules | https://semgrep.dev · https://github.com/semgrep/semgrep |
| OSV-Scanner (Google) | Checks dependencies against the OSV vulnerability database | https://google.github.io/osv-scanner/ |
| `npm audit` | Known-vulnerable npm deps. Pair with `--ignore-scripts` so nothing runs | https://docs.npmjs.com/cli/v10/commands/npm-audit · https://docs.npmjs.com/cli/v10/using-npm/config#ignore-scripts |
| Socket | Flags risky npm package behavior (install scripts, network, obfuscation) | https://docs.socket.dev · https://github.com/SocketDev/socket-cli |
| GitHub Dependabot | Alerts/PRs for vulnerable dependencies in your own repos | https://docs.github.com/en/code-security/dependabot |
| VS Code Workspace Trust | Restricted Mode blocks tasks and other auto-run features | https://code.visualstudio.com/docs/editing/workspaces/workspace-trust |

Note: osv-scanner, semgrep and gitleaks need to be installed first. Install
them from the official links above - not from inside the suspicious repo.
