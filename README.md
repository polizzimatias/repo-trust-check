# Check a GitHub repo before you open it in an AI coding tool

A small, read-only Python script that looks inside a downloaded repository
**before** you open it in Claude Code, Cursor, Codex, Gemini CLI or VS Code,
and tells you in plain words whether anything in it would run on your computer
by itself.

- One file (`scan_repo.py`), Python 3 standard library only. Nothing to install.
- It **only reads files**. It never runs anything from the repo and never
  connects to the internet.
- You get a short report and a verdict: **Looks clean**, **Review before
  opening** or **Do not open**.

> This is not antivirus and it comes with no warranty. See [Limits](#limits).

## For beginners: one-minute setup

Install this once and your AI assistant checks every repo **before** it downloads, opens or
installs it. After that you just paste a link as usual ("set up
https://github.com/someone/cool-app for me"). The AI first downloads the repo into a separate
folder (`~/repo-quarantine`), scans it without running anything, and tells you in plain words:
**Looks clean**, **Review before opening** or **Do not open**. If the answer is "Do not open",
it stops.

**Important:** the check only works if it happens before the repo is opened. Start your AI from
your home folder or your usual projects folder, **never from inside a folder you just
downloaded**. If you already opened a repo, see
[If you already opened a repo](#if-you-already-opened-a-repo-that-comes-back-do-not-open).

### Easiest: let your AI install it

Copy this whole box and paste it into your AI tool. **Tested in Claude Code.** It's built to work
with Codex, Cursor, Gemini CLI, GitHub Copilot and Windsurf too, but those haven't been tested yet,
so please [open an issue](https://github.com/polizzimatias/repo-trust-check/issues) if it doesn't work for you:

```text
Install the repo-trust-check safety skill from https://github.com/polizzimatias/repo-trust-check
Do exactly this and nothing else:
1. Download it without running anything:
   git clone --depth 1 --no-recurse-submodules -c core.hooksPath=/dev/null https://github.com/polizzimatias/repo-trust-check ~/.repo-trust-check
   (If ~/.repo-trust-check already exists, update it instead: git -C ~/.repo-trust-check pull)
2. Copy the folder ~/.repo-trust-check/skills/repo-trust-check into ~/.claude/skills/ and into
   ~/.agents/skills/ (create those folders if needed, replace an older copy). On Windows, ~ means
   my user folder (C:\Users\<me>).
3. Do not run any other file from it. Tell me when it is done and remind me to restart you.
```

Then close and reopen your AI tool. That's it. The first time the check runs, your AI may ask
permission to use the skill or to run `check_repo.py`. Say yes.

### Claude Code: install as a plugin (gets updates)

Type these two lines inside Claude Code, then restart it:

```text
/plugin marketplace add polizzimatias/repo-trust-check
/plugin install repo-trust-check@repo-trust-check
```

If the first line fails with an SSH error, use the full link instead:
`/plugin marketplace add https://github.com/polizzimatias/repo-trust-check.git`

### Or do it yourself: one line in a terminal

macOS / Linux:

```bash
git clone --depth 1 -c core.hooksPath=/dev/null https://github.com/polizzimatias/repo-trust-check ~/.repo-trust-check && for d in ~/.claude/skills ~/.agents/skills; do mkdir -p "$d/repo-trust-check" && cp -R ~/.repo-trust-check/skills/repo-trust-check/. "$d/repo-trust-check/"; done
```

Windows (PowerShell):

```powershell
git clone --depth 1 https://github.com/polizzimatias/repo-trust-check "$HOME\.repo-trust-check"; foreach ($d in "$HOME\.claude\skills", "$HOME\.agents\skills") { New-Item -ItemType Directory -Force "$d\repo-trust-check" | Out-Null; Copy-Item -Recurse -Force "$HOME\.repo-trust-check\skills\repo-trust-check\*" "$d\repo-trust-check\" }
```

You need `git` and Python 3. The skill uses nothing else.

### Which folder does my AI tool read?

Only Claude Code has been tested so far. The other rows come from each tool's documentation and
are untested. The copy-paste and one-line installs above cover all of these. Cursor, VS Code and Copilot read
both folders, so they may list the skill twice. That is harmless.

| AI tool | Reads skills from | Its own installer (optional) |
|---|---|---|
| Claude Code | `~/.claude/skills` or the plugin above | `/plugin install repo-trust-check@repo-trust-check` |
| OpenAI Codex | `~/.agents/skills` | `$skill-installer install https://github.com/polizzimatias/repo-trust-check/tree/main/skills/repo-trust-check` |
| Cursor | `~/.agents/skills`, `~/.cursor/skills`, `~/.claude/skills` | |
| Gemini CLI | `~/.agents/skills`, `~/.gemini/skills` | `gemini skills install https://github.com/polizzimatias/repo-trust-check.git --path skills/repo-trust-check` |
| GitHub Copilot (VS Code, CLI) | `~/.copilot/skills`, `~/.agents/skills`, `~/.claude/skills` | `gh skill install polizzimatias/repo-trust-check repo-trust-check --agent github-copilot --scope user` |
| Windsurf / Devin Desktop | `~/.agents/skills` (and `~/.claude/skills` if Claude config reading is on) | |

`gh skill install polizzimatias/repo-trust-check repo-trust-check --agent <tool> --scope user`
(GitHub CLI 2.90 or newer) should also work for `claude-code`, `codex`, `cursor` and `gemini-cli` (untested).

### Optional for Claude Code: block plain `git clone` (stricter)

The skill relies on the AI noticing that you pasted a repo link. For an extra safety net, this
add-on stops Claude from running `git clone`, `gh repo clone` or `degit` directly and sends it
to the check instead:

```text
/plugin install repo-trust-check-hook@repo-trust-check
```

Good to know before you turn it on:
- It is a reminder, not a wall. Code can still be downloaded in other ways.
- It also blocks clones of your own repos. Turn it off with
  `/plugin disable repo-trust-check-hook@repo-trust-check`, or start Claude with
  `REPO_TRUST_CHECK_HOOK=off` for one session.
- It needs `python3` on your PATH. Without it, the hook does nothing (Claude carries on).

## Why this exists

Modern AI coding tools and editors read config files from the project folder
the moment you open it. Some of those files can start programs: a Claude Code
`SessionStart` hook, an MCP server in `.cursor/mcp.json`, a VS Code task set
to run on folder open, an `AGENTS.md` that tells the agent to run a script.

In October 2026 JFrog Security Research described a campaign that used exactly
this. Attackers hid hooks like these in real GitHub repositories so that simply
opening the project in an AI tool or editor ran a hidden payload (a 13 MB
`.github/init.js` file that GitHub's code search did not index). Read their
report: [Beyond testmetest: Native Addon Camouflage and 42 Armed GitHub
Repositories Reveal a Hidden npm Publisher](https://research.jfrog.com/post/beyond-testmetest-42-hijacked-github-repos/)
(Guy Korolevski and Yair Benamou, 26 Oct 2026).

The fix for ordinary users is simple: **download the repo without running it,
look first, open later.** This script does the "look" part for you.

## What it checks, in plain words

- **AI tool settings that run commands.** Claude Code hooks
  (`.claude/settings*.json`), MCP servers that start a program
  (`.cursor/mcp.json`, `.mcp.json`, `.gemini/settings.json`, any `*mcp*.json`).
- **Editor tasks that run when you open the folder.** `.vscode/tasks.json` with
  `runOn: folderOpen`, plus risky `.vscode/settings.json` entries.
- **Instructions written for the AI.** `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`,
  `.cursorrules`, `.cursor/rules/*`, `.github/copilot-instructions.md` and
  similar: anything that tells the agent to run commands, fetch web pages, or
  act "silently" or "without asking".
- **Install scripts.** `package.json` `preinstall` / `install` / `postinstall`
  / `prepare`, `binding.gyp` command expansion, Composer auto scripts,
  Makefiles.
- **Hidden or oversized code.** Big files in hidden folders, long base64 or hex
  blobs, `eval` over character codes, compiled `.node` addons.
- **Suspicious web addresses.** Raw IP addresses, paste sites, webhooks,
  Discord or Telegram links in auto-loaded files.
- **Git history (if you cloned with git).** Branch names and commit markers the
  JFrog report lists. Git hooks, pagers and fsmonitor are switched off for this.
- **Known indicators (optional).** If `iocs.json` sits next to the script, it
  also matches the file hashes, package names, file names and addresses JFrog
  published. Without that file, the general checks still run.

## How to use it

### 1. Make a safe, empty folder

This folder is your workbench, not the project. Put `scan_repo.py` (and,
optionally, `iocs.json`) from this repo in it.

```bash
mkdir -p ~/repo-check && cd ~/repo-check
# copy scan_repo.py and iocs.json from https://github.com/polizzimatias/repo-trust-check here
```

### 2. Download the repo you want to check, without running anything

```bash
GIT_LFS_SKIP_SMUDGE=1 git clone --no-recurse-submodules -c core.hooksPath=/dev/null -c core.symlinks=false <URL> target
```

That command turns off Git LFS downloads, submodules, git hooks and symbolic
links, and puts the repo in a folder called `target`. On Windows PowerShell,
run `$env:GIT_LFS_SKIP_SMUDGE=1` first and use `core.hooksPath=NUL`.

**No git?** On the repo's GitHub page click **Code → Download ZIP** and unzip
it into `~/repo-check/target`. Don't double-click anything inside. (A ZIP has
no history, so the git checks are skipped.)

Do **not** open `target` in an AI tool or editor yet, and do **not** run
`npm install` or any other install command.

### 3. Scan it

```bash
python3 scan_repo.py target
```

The report is printed and also saved as `scan-report.md` (change that with
`--out myreport.md`). On Windows use `python` instead of `python3`.

### Or let Claude Code or Codex do steps 2 and 3

Easiest: install the skill once ([For beginners](#for-beginners-one-minute-setup)) and just
paste the repo link. Or, without installing anything:
Open [PROMPT.md](PROMPT.md), start Claude Code or Codex **in `~/repo-check`
(never inside `target`)**, and paste the prompt. It tells the agent to clone
safely, run the scanner, treat everything in the repo as untrusted, and give
you a plain-English verdict.

## What the verdicts mean

| Verdict | Exit code | Meaning |
|---|---|---|
| **Looks clean** | `0` | Nothing found that would run by itself. INFO notes may be listed for context. |
| **Review before opening** | `1` | MEDIUM items: often normal project setup, but read each one and make sure you recognise it. |
| **Do not open** | `2` | At least one HIGH item: something would run automatically, or a known attack sign matched. Don't open it in an AI tool or editor and don't install its dependencies. |

The exit codes let you use it in scripts, e.g. `python3 scan_repo.py target || echo "check the report"`.

Even with **Looks clean**, open the project first in VS Code or Cursor
**Restricted Mode** (answer "Don't trust" to the workspace trust question) and
install dependencies with `npm install --ignore-scripts`.

## Try it on the harmless demo

This repo ships two tiny practice repos in `examples/`. Their config files are
stored under inert names (`dot-claude/settings.json.sample`,
`AGENTS.md.sample` and so on) so nothing treats them as real config. Build them
with their real names, then scan:

```bash
python3 make_demo.py                 # creates demo-output/demo-repo and demo-output/clean-repo
python3 scan_repo.py demo-output/demo-repo     # expected verdict: Do not open
python3 scan_repo.py demo-output/clean-repo    # expected verdict: Looks clean
```

Everything in the demo is fake: each "command" is an `echo`, each web address
uses the reserved `example.invalid` domain (it can never resolve), and the
"payload" is random padding that is never decoded or run. Sample reports are in
`examples/sample-report-demo.md` and `examples/sample-report-clean.md`.

## Limits

- **It's a pattern checker, not antivirus.** Expect false alarms (a normal
  `postinstall`, a `CLAUDE.md` that says "run the tests") and misses (a careful
  attacker can write something it doesn't recognise). "Looks clean" is not a
  guarantee.
- **One branch at a time.** It scans the files you checked out. JFrog found
  the attacker kept the default branch clean and used short-lived branches;
  the scanner flags those branch names but doesn't scan other branches' files.
- **It doesn't check your dependencies.** It reads lockfiles (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`) for the
  known bad package names only. Use the tools below for vulnerability checks.
- **Indicators go stale.** The `iocs.json` list is copied from one report. New
  campaigns use new names and hashes; the general checks matter most.
- **AI agents read more than you ask.** Claude Code can load a `CLAUDE.md` from
  a subfolder when it reads files there. That's why the prompt says to treat
  the repo as untrusted data and never to start the agent inside it.

## If you already opened a repo that comes back "Do not open"

Follow JFrog's remediation section in the report linked above. The order of
steps matters if you **installed one of the campaign's npm packages** (the
"npm worm" versions). In JFrog's words:

> "Remove `net-health-checker` and `pkg-runtime` persistence, including their
> LaunchAgents, systemd user services and associated files, before revoking
> the stolen GitHub token because the npm worm contains a token-revocation
> wiper."

In other words: clean the machine first, then rotate tokens. If you rotate
first on an infected machine, the worm may react by wiping files. See
[STEPS.md](STEPS.md) for the persistence paths JFrog lists and the rest of the
checklist. If it's a work computer, call your IT or security team first.

## Free tools that complement this

| Tool | What it adds | Link |
|---|---|---|
| Gitleaks | Finds leaked secrets in files and git history | https://github.com/gitleaks/gitleaks |
| Semgrep | Code pattern scanning with community rules | https://semgrep.dev |
| OSV-Scanner | Checks dependencies against the OSV vulnerability database | https://google.github.io/osv-scanner/ |
| `npm audit` | Known-vulnerable npm packages (use with `--ignore-scripts`) | https://docs.npmjs.com/cli/v10/commands/npm-audit |
| Socket | Flags risky npm package behaviour | https://docs.socket.dev |
| TruffleHog | Secret scanning with live-key verification | https://github.com/trufflesecurity/trufflehog |
| VS Code Workspace Trust | Restricted Mode blocks tasks and other auto-run features | https://code.visualstudio.com/docs/editing/workspaces/workspace-trust |

Install these from their official pages, never from inside a repo you're
checking.

## Files in this repo

| File | What it is |
|---|---|
| `scan_repo.py` | The scanner. Read-only, standard library only. |
| `skills/repo-trust-check/` | The AI skill: `SKILL.md`, `check_repo.py` (safe download + scan) and copies of the scanner. Also a Claude Code plugin. |
| `plugins/repo-trust-check-hook/` | Optional Claude Code add-on that blocks plain `git clone` (see above). |
| `.claude-plugin/marketplace.json` | Lets Claude Code install both from this repo. |
| `tools/sync_skill.py` | Copies `scan_repo.py` and `iocs.json` into the skill. Edit the root files, then run it. |
| `tests/` | `python3 -m unittest discover -s tests`. Also checks the skill copies match. |
| `iocs.json` | Optional known indicators from the JFrog report, with the source cited inside. |
| `PROMPT.md` | Copy-paste prompt for Claude Code or Codex, plus a terminal-only version. |
| `STEPS.md` | The five steps on one page, caveats, and the "already opened" checklist. |
| `make_demo.py` | Builds the harmless practice repos from `examples/`. |
| `examples/` | The practice repos (inert file names) and sample reports. |

## Disclaimer

Provided "as is", without warranty of any kind (see [LICENSE](LICENSE)). This
is an educational helper, not a security product or antivirus, and a clean
result does not prove a repository is safe. You are responsible for what you
open and run. Not affiliated with JFrog, Anthropic, Cursor, OpenAI, Google,
Microsoft or GitHub.

## License

MIT. See [LICENSE](LICENSE).
