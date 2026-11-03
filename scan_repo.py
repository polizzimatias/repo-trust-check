#!/usr/bin/env python3
"""
scan_repo.py - a simple, READ-ONLY check of a downloaded repo BEFORE you open it
in an AI coding tool (Claude Code, Cursor, Codex, Gemini CLI, VS Code).

Usage:   python3 scan_repo.py /path/to/repo [--out scan-report.md]

Safety promises:
  * Python 3 standard library only. No installs, no network calls.
  * Never executes anything from the target repo. It only READS files.
  * The only external command is an optional, read-only `git log` / `git for-each-ref`
    with repo hooks, pagers and fsmonitor disabled.

This is a heuristic helper, not antivirus. A clean result is not a guarantee.
Threat background: JFrog, "Beyond testmetest" (26 Oct 2026)
https://research.jfrog.com/post/beyond-testmetest-42-hijacked-github-repos/
Exit codes: 0 = looks clean, 1 = review findings (MEDIUM), 2 = HIGH findings.
Optional: iocs.json next to this file adds JFrog's published indicators.

MIT License. Copyright 2026 Matias Polizzi. https://github.com/polizzimatias/repo-trust-check
"""
import hashlib, json, math, os, re, subprocess, sys
from datetime import datetime

BIG_FILE = 1 * 1024 * 1024        # 1 MB: "oversized" threshold
READ_LIMIT = 4 * 1024 * 1024      # read at most 4 MB of any file for text checks
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__",       # dependencies / VCS internals
             ".next", ".nuxt", ".turbo", ".cache", ".svelte-kit", "coverage"}  # local build output (normally not in git)
SEV_ORDER = ["HIGH", "MEDIUM", "INFO"]

# ---------------------------------------------------------------- IOCs
# Optional indicators from JFrog's report live in iocs.json next to this script (with the
# source cited inside). Without that file the scanner still runs its generic checks.
HERE = os.path.dirname(os.path.abspath(__file__))
def _refang(v): return v.replace("[.]", ".").replace("hxxp", "http")
def load_iocs():
    try:
        with open(os.path.join(HERE, "iocs.json"), encoding="utf-8") as fh: return json.load(fh)
    except (OSError, ValueError): return {}
IOCS = load_iocs()
IOC_NETWORK = [_refang(v) for v in IOCS.get("network", [])]
IOC_STRINGS = IOCS.get("strings", [])
IOC_PACKAGES = IOCS.get("packages", [])
IOC_SHA256 = IOCS.get("sha256", {})
IOC_SHA_PREFIX = IOCS.get("sha256_prefixes", {})
IOC_PATHS = set(IOCS.get("file_paths", [])); IOC_NAMES = set(IOCS.get("file_names", []))
MARK_HIGH = IOCS.get("commit_markers_high", []); MARK_MED = IOCS.get("commit_markers_medium", [])
BRANCH_PREFIXES = IOCS.get("branch_prefixes", [])

def _sha(path):
    try:
        with open(path, "rb") as fh: return hashlib.sha256(fh.read()).hexdigest()
    except OSError: return ""
# The scanner's own files contain the IOC strings on purpose; skip IOC text matching on exact copies.
SELF_HASHES = {h for h in (_sha(os.path.abspath(__file__)), _sha(os.path.join(HERE, "iocs.json"))) if h}

# ---------------------------------------------------------------- patterns
# Commands that run code, download things, or decode hidden content.
DANGER = [
    (r"\b(curl|wget|iwr|Invoke-WebRequest)\b[^\n|]*\|\s*(ba|z)?sh\b", "downloads a script and pipes it straight into a shell"),
    (r"\b(curl|wget)\b", "downloads something from the internet"),
    (r"\b(ba|z)?sh\s+-c\b", "runs a shell command string"),
    (r"\b(powershell|pwsh)(\.exe)?\b|\biex\b|Invoke-Expression", "runs PowerShell"),
    (r"\bnode\s+(-e|--eval|-p)\b|\bpython3?\s+-c\b|\bbun\s+run\s+-(\s|$)|\bperl\s+-e\b", "runs inline code"),
    (r"\b(node|bun|deno|python3?|ruby|sh|bash)\s+\.?[\w./-]*\.(js|mjs|cjs|ts|py|rb|sh)\b", "runs a script file from the repo"),
    (r"\b(npx|uvx|bunx|pnpm\s+dlx|pipx\s+run)\b", "downloads and runs a package on the fly"),
    (r"base64\s+(-d|--decode)|FromBase64String|certutil\s+-decode|\batob\(", "decodes hidden (base64) content"),
    (r"\b(nohup|setsid|disown|crontab|launchctl|systemctl\s+--user)\b|LaunchAgents", "runs in the background or installs persistence"),
    (r"\b(GITHUB_TOKEN|GH_TOKEN|NPM_TOKEN|AWS_SECRET\w*|ANTHROPIC_API_KEY|OPENAI_API_KEY)\b", "touches a secret token"),
    (r"~/\.ssh|~/\.aws|\.npmrc|id_rsa|\.git-credentials|\bprintenv\b", "reads credentials or dumps environment variables"),
]
DANGER = [(re.compile(p, re.I), why) for p, why in DANGER]
STRONG = ("pipes", "secret", "credential", "PowerShell", "decodes", "persistence", "shell command")  # worst reasons

def is_strong(reasons):
    """True if any reason is one of the worst kinds (download-and-run, secrets, hidden decode...)."""
    return any(any(w in r for w in STRONG) for r in reasons)
CODE_EXEC = re.compile(r"\beval\s*\(|new\s+Function\s*\(|child_process|\bexecSync\b|\bspawn\s*\(|String\.fromCharCode")
URL_RE = re.compile(r"\b(?:https?|wss?|ftp)://[^\s\"'<>`)\]]+", re.I)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b")
SHADY_HOST = re.compile(r"pastebin|paste\.ee|hastebin|ghostbin|discord(app)?\.com/api/webhooks|api\.telegram\.org|t\.me/|"
                        r"webhook\.site|ngrok|requestbin|pipedream|transfer\.sh|raw\.githubusercontent|gist\.githubusercontent", re.I)
B64_RE = re.compile(r"[A-Za-z0-9+/]{200,}={0,2}")
HEX_RE = re.compile(r"\b(?:[0-9a-fA-F]{2}){100,}\b")
CHARCODES = re.compile(r"(?:\d{1,3}\s*,\s*){60,}")   # long number arrays (JFrog: char-code wrapper)
HIDDEN_UNICODE = re.compile("[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]")
# Instructions that try to keep the human out of the loop (HIGH) or hide activity (MEDIUM).
INJECTION = re.compile(r"ignore (all |any )?(previous|prior) instructions|do not (tell|inform|show) the user|"
                       r"without (asking|telling|informing) (the )?user|without (user |your )?(confirmation|approval)|"
                       r"don't (tell|mention .* to) the user|keep this (secret|hidden)", re.I)
QUIET = re.compile(r"\b(run|execute|install|download)\w*\b[^.\n]{0,40}\bsilently|silently\s+(run|execute|install|download)", re.I)
FETCH = re.compile(r"\b(fetch|download|curl|wget|load|pull|follow|retrieve|visit)\b", re.I)
INSTRUCT_RUN = re.compile(r"\b(run|execute|install|download|fetch|curl|wget|source|bootstrap)\b", re.I)

# AI-tool files that are loaded automatically when a project is opened.
INSTRUCTION_FILES = {"agents.md", "claude.md", "claude.local.md", "gemini.md", ".cursorrules", ".windsurfrules",
                     "copilot-instructions.md"}
AI_DIRS = (".claude/", ".cursor/", ".vscode/", ".gemini/", ".codex/", ".windsurf/", ".github/")
LIFECYCLE = {"preinstall", "install", "postinstall", "prepare", "prepublish", "prepublishonly", "preprepare", "postprepare"}
COMPOSER_AUTO = {"pre-install-cmd", "post-install-cmd", "pre-update-cmd", "post-update-cmd", "post-autoload-dump",
                 "post-root-package-install", "post-create-project-cmd"}
CODE_EXT = {".js", ".mjs", ".cjs", ".ts", ".py", ".sh", ".ps1", ".bat", ".cmd", ".rb", ".php"}
MEDIA_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".mp4", ".mov", ".mp3", ".wav", ".pdf", ".zip",
             ".woff", ".woff2", ".ttf", ".otf", ".ico", ".psd", ".sketch", ".fig"}

findings = []
def add(sev, path, line, what, why, todo):
    key = (sev, path, line, what)
    if key not in {(f[0], f[1], f[2], f[3]) for f in findings}:
        findings.append((sev, path, line, what, why, todo))

# ---------------------------------------------------------------- helpers
def read_text(p):
    with open(p, "rb") as fh:
        raw = fh.read(READ_LIMIT)
    if b"\x00" in raw[:8192]:
        return None                                  # binary file
    return raw.decode("utf-8", errors="replace")

def entropy(data):
    if not data: return 0.0
    counts = [0] * 256
    for b in data: counts[b] += 1
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts if c)

def strip_jsonc(text):
    """Remove // and /* */ comments and trailing commas so VS Code style JSON parses."""
    out, i, n, in_str = [], 0, len(text), False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n: out.append(text[i + 1]); i += 1
            elif c == '"': in_str = False
        elif c == '"': in_str = True; out.append(c)
        elif text.startswith("//", i):
            while i < n and text[i] != "\n": i += 1
            continue
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2); i = n if j < 0 else j + 2
            continue
        else: out.append(c)
        i += 1
    return re.sub(r",\s*([}\]])", r"\1", "".join(out))

def load_json(text):
    try: return json.loads(strip_jsonc(text))
    except Exception: return None

def line_of(text, needle):
    """1-based line number where `needle` first appears (0 if not found)."""
    idx = text.find(needle) if needle else -1
    return text.count("\n", 0, idx) + 1 if idx >= 0 else 0

def danger_reasons(s):
    return [why for rx, why in DANGER if rx.search(s)]

def walk_json(obj, keypath=""):
    """Yield (keypath, string) for every string value inside a JSON object."""
    if isinstance(obj, dict):
        for k, v in obj.items(): yield from walk_json(v, f"{keypath}.{k}" if keypath else str(k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj): yield from walk_json(v, f"{keypath}[{i}]")
    elif isinstance(obj, str):
        yield keypath, obj

def short(s, n=110):
    s = " ".join(s.split())
    return s if len(s) <= n else s[:n] + "..."

# ---------------------------------------------------------------- checks
def check_network(rel, text, auto):
    """URLs and IPs in config/scripts. `auto` = file that is loaded or run automatically."""
    for no, line in enumerate(text.splitlines(), 1):
        if len(line) > 5000: continue                # handled by the obfuscation check
        for m in URL_RE.finditer(line):
            url = m.group(0)
            if re.match(r"\w+://(localhost|127\.|0\.0\.0\.0|\[::1\])", url): continue   # your own computer
            port = re.match(r"\w+://[^/:]+:(\d+)", url)
            if SHADY_HOST.search(url):
                add("HIGH" if auto else "MEDIUM", rel, no, f"Link to a paste/webhook/raw-file host: {short(url, 80)}",
                    "These hosts are often used to hide payloads or to send stolen data out.", "Find out why it is there before opening the repo.")
            elif port and port.group(1) not in ("80", "443") or re.match(r"\w+://\d+\.\d+\.\d+\.\d+", url):
                add("HIGH" if auto else "MEDIUM", rel, no, f"Link to a raw IP address or unusual port: {short(url, 80)}",
                    "Real projects almost always use named domains; raw IPs are a common sign of attacker servers.", "Treat as suspicious.")
            elif auto and not any(f[1] == rel and f[2] == no for f in findings):
                add("INFO", rel, no, f"Web address in an auto-loaded file: {short(url, 80)}",
                    "An AI tool or editor may contact this address when the project opens.", "Make sure you recognise the domain.")
        for m in IP_RE.finditer(line):
            ip = m.group(0).split(":")[0]
            if ip.startswith(("127.", "0.", "10.", "192.168.")) or ip == "255.255.255.255": continue
            if all(0 <= int(x) <= 255 for x in ip.split(".")) and not URL_RE.search(line):
                add("MEDIUM", rel, no, f"Raw IP address: {m.group(0)}", "Hard-coded public IPs can point at attacker servers.", "Check what it is.")

def check_commands(rel, text, label, high_if_danger=True):
    """Flag lines in an auto-run context that contain dangerous command patterns."""
    for no, line in enumerate(text.splitlines(), 1):
        reasons = danger_reasons(line)
        if reasons:
            add("HIGH" if high_if_danger else "MEDIUM", rel, no, f"{label}: `{short(line.strip())}`",
                "This " + "; ".join(sorted(set(reasons))) + ".",
                "Do not open this project in an AI tool or editor until you understand this line.")

def check_claude_settings(rel, text, data):
    hooks = data.get("hooks") if isinstance(data, dict) else None
    if isinstance(hooks, dict):
        for event, entries in hooks.items():
            for _, cmd in walk_json(entries):
                if cmd in ("command", "*") or len(cmd) < 2: continue
                sev = "HIGH" if danger_reasons(cmd) or event in ("SessionStart", "UserPromptSubmit") else "MEDIUM"
                add(sev, rel, line_of(text, cmd[:25]) or line_of(text, event), f"Claude Code `{event}` hook runs: `{short(cmd)}`",
                    "Hooks run automatically on your computer when Claude Code starts or acts in this folder. "
                    "JFrog found this exact trick (a SessionStart hook running `node .github/init.js`).",
                    "Do not start Claude Code in this folder. Read the command and the file it runs first.")
    if isinstance(data, dict) and data.get("enableAllProjectMcpServers"):
        add("HIGH", rel, line_of(text, "enableAllProjectMcpServers"), "Auto-approves every MCP server in the project",
            "Any tool server defined in the repo would start without asking you.", "Remove this setting or don't open the repo.")
    allow = (data.get("permissions") or {}).get("allow", []) if isinstance(data, dict) else []
    for a in allow if isinstance(allow, list) else []:
        if isinstance(a, str) and re.match(r"Bash\((\*|.*:\*)?\)$|^Bash$", a):
            add("MEDIUM", rel, line_of(text, a), f"Pre-approves shell commands: `{a}`",
                "The AI could run commands without asking you.", "Remove broad shell permissions from repo settings.")

def check_mcp(rel, text, data):
    servers = data.get("mcpServers") or data.get("servers") if isinstance(data, dict) else None
    if not isinstance(servers, dict): return
    for name, cfg in servers.items():
        if not isinstance(cfg, dict): continue
        cmd = " ".join(str(x) for x in [cfg.get("command", "")] + list(cfg.get("args", []) or []))
        url = cfg.get("url") or cfg.get("serverUrl") or ""
        if cmd.strip():
            sev = "HIGH" if danger_reasons(cmd) or URL_RE.search(cmd) else "MEDIUM"
            add(sev, rel, line_of(text, f'"{name}"'), f"MCP server `{name}` starts a program: `{short(cmd)}`",
                "A local MCP server is a program the AI tool launches on your computer, often as soon as the project opens.",
                "Only keep MCP servers you added yourself or fully trust.")
        if url:
            add("MEDIUM", rel, line_of(text, url), f"MCP server `{name}` connects to {short(url, 80)}",
                "Your AI tool would send data to this remote server.", "Make sure you know and trust this service.")
        if "env" in cfg:
            add("MEDIUM", rel, line_of(text, '"env"'), f"MCP server `{name}` sets environment variables",
                "Environment variables can pass your tokens to the server.", "Check which variables are passed.")

def check_vscode(rel, text, data):
    name = os.path.basename(rel).lower()
    if name == "tasks.json" and isinstance(data, dict):
        for t in data.get("tasks", []) or []:
            if isinstance(t, dict) and (t.get("runOptions") or {}).get("runOn") == "folderOpen":
                cmd = " ".join(str(x) for x in [t.get("command", "")] + list(t.get("args", []) or []))
                add("HIGH", rel, line_of(text, "folderOpen"), f"VS Code/Cursor task runs when the folder opens: `{short(cmd)}`",
                    "`runOn: folderOpen` makes the editor run this command the moment you open the project (if you trust the folder).",
                    "Don't open this folder in VS Code or Cursor. If you must, choose 'Don't Trust' (Restricted Mode).")
    if name == "settings.json" and isinstance(data, dict):
        for key, val in walk_json(data):
            k = key.lower()
            if "allowautomatictasks" in k and str(val).lower() == "on":
                add("HIGH", rel, line_of(text, "allowAutomaticTasks"), "Turns on automatic tasks",
                    "Lets tasks run on folder open without asking.", "Remove this setting.")
            elif re.search(r"terminal\.integrated\.(env|shell|profiles|automationprofile)|\.(path|executable|interpreterpath|runtime)$", k):
                add("MEDIUM", rel, line_of(text, key.split(".")[0]), f"Editor setting points at a program: `{key}` = `{short(val, 60)}`",
                    "Workspace settings can make the editor launch a program from inside the repo.", "Check the program it points to.")
    if name == "extensions.json" and isinstance(data, dict):
        recs = data.get("recommendations") or []
        if recs:
            add("INFO", rel, line_of(text, "recommendations"), "Recommends extensions: " + short(", ".join(map(str, recs)), 120),
                "Extensions are code that runs in your editor.", "Only install ones from publishers you recognise.")
    if name == "launch.json":
        add("INFO", rel, 1, "Debug launch config present", "Runs only when you start debugging.", "Glance at it before pressing Run/Debug.")

def check_instruction_file(rel, text):
    """AGENTS.md / CLAUDE.md / .cursorrules etc: text the AI reads and may obey."""
    in_code, script_lines = False, []
    for no, line in enumerate(text.splitlines(), 1):
        if line.strip().startswith("```"): in_code = not in_code
        if HIDDEN_UNICODE.search(line):
            add("HIGH", rel, no, "Invisible characters in AI instructions",
                "Hidden Unicode can smuggle instructions you cannot see on screen.", "Do not use this repo with an AI agent until cleaned.")
        if INJECTION.search(line):
            add("HIGH", rel, no, f"Instruction tries to act behind your back: `{short(line.strip())}`",
                "It tells the AI to skip asking you or hide what it does.", "Do not open this repo with an AI agent.")
        elif QUIET.search(line):
            add("MEDIUM", rel, no, f"Instruction asks the agent to run things silently: `{short(line.strip())}`",
                "Quiet background actions are harder for you to notice.", "Check what it runs.")
        reasons = danger_reasons(line)
        if reasons and all("script file from the repo" in x for x in reasons):
            script_lines.append(no)                    # common in real projects; summarised once below
        elif reasons and (INSTRUCT_RUN.search(line) or in_code):
            add("HIGH" if is_strong(reasons) else "MEDIUM",
                rel, no, f"AI instruction file tells the agent to run: `{short(line.strip())}`",
                "AI agents read this file automatically and may run the command for you.", "Read it yourself; don't let an agent follow it.")
        elif FETCH.search(line) and URL_RE.search(line) and not re.search(r"://(localhost|127\.0\.0\.1)", line):
            add("MEDIUM", rel, no, f"AI instruction mentions fetching a URL: `{short(line.strip())}`",
                "The agent may download content from this address.", "Check the address.")
    if script_lines:
        add("MEDIUM" if len(script_lines) < 10 else "INFO", rel, script_lines[0],
            f"AI instructions tell the agent to run {len(script_lines)} script(s) from the repo (lines {', '.join(map(str, script_lines[:8]))}"
            + ("..." if len(script_lines) > 8 else "") + ")",
            "Normal for many projects, but an agent may run them for you. In a hostile repo these scripts are the payload.",
            "Open those scripts and read them before letting an agent run them.")

def check_package_json(rel, text, data):
    if not isinstance(data, dict): return
    for name, cmd in (data.get("scripts") or {}).items():
        if not isinstance(cmd, str): continue
        reasons = danger_reasons(cmd)
        if name.lower() in LIFECYCLE:
            add("HIGH" if is_strong(reasons) else "MEDIUM", rel, line_of(text, f'"{name}"'), f"npm `{name}` script runs on install: `{short(cmd)}`",
                "Install scripts run automatically during `npm install`." + (" This one " + "; ".join(reasons) + "." if reasons else ""),
                "Never run `npm install` on an untrusted repo; use `npm install --ignore-scripts` after review.")
        elif [x for x in reasons if "script file from the repo" not in x]:   # `node scripts/x.js` is normal
            add("MEDIUM", rel, line_of(text, f'"{name}"'), f"npm script `{name}`: `{short(cmd)}`",
                "This script " + "; ".join(reasons) + ".", "Don't run it until you understand it.")
    deps = {}
    for k in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        deps.update(data.get(k) or {})
    for pkg in deps:
        if pkg in IOC_PACKAGES:
            add("HIGH", rel, line_of(text, pkg), f"Depends on `{pkg}` (named in JFrog's testmetest report)",
                "JFrog lists malicious versions of this package.", "Do not install. See JFrog's guidance.")

def check_code_blob(rel, raw_size, text, hidden, data):
    """Oversized / minified / encoded / high-entropy content."""
    ext = os.path.splitext(rel)[1].lower()
    minified_ok = ".min." in rel or "/dist/" in f"/{rel}" or "/build/" in f"/{rel}" or "/vendor/" in f"/{rel}"
    if text is not None:
        longest = max((len(l) for l in text.splitlines()), default=0)
        b64 = max((len(m.group(0)) for m in B64_RE.finditer(text)), default=0)
        hexrun = max((len(m.group(0)) for m in HEX_RE.finditer(text)), default=0)
        codes = bool(CHARCODES.search(text))
        executes = bool(CODE_EXEC.search(text))
        obf = b64 >= 1000 or hexrun >= 1000 or codes or (ext in CODE_EXT and longest > 5000 and not minified_ok)
        if obf:
            sev = "HIGH" if (executes and (hidden or ext in CODE_EXT)) or (hidden and raw_size > BIG_FILE) else "MEDIUM"
            bits = [f"a {b64:,}-char base64 run" if b64 >= 1000 else "", f"a {hexrun:,}-char hex run" if hexrun >= 1000 else "",
                    "long number arrays (char-code encoding)" if codes else "", f"a {longest:,}-char single line" if longest > 5000 else ""]
            add(sev, rel, 1, "Encoded or obfuscated content: " + ", ".join(b for b in bits if b) + (" + code-execution calls (eval/exec)" if executes else ""),
                "Hiding code this way is how payloads avoid review; JFrog's wrapper used eval over encoded char codes.",
                "Do not run or open this file in a tool that executes it.")
        elif b64 >= 200 and (hidden or ext in CODE_EXT):
            add("INFO", rel, 1, f"Base64-looking string ({b64} chars)", "Could be a key, image or hidden code.", "Glance at it.")
        if ext in CODE_EXT and executes and hidden and not obf:
            add("MEDIUM", rel, 1, "Script in a hidden folder can run other programs (eval/exec/child_process)",
                "Hidden-folder scripts are where JFrog found the payload (`.github/init.js`).", "Read it before running anything.")
    if raw_size > BIG_FILE and os.path.splitext(rel)[1].lower() not in MEDIA_EXT:
        sev = "HIGH" if hidden else "MEDIUM"
        add(sev, rel, 0, f"Oversized file: {raw_size / 1048576:.1f} MB" + (" in a hidden/config folder" if hidden else ""),
            "JFrog's payloads were 12.9-13.7 MB files that GitHub search did not index. Big code files in odd places deserve a look.",
            "Find out what this file is; don't run it.")
    if data is not None and len(data) >= 4096 and entropy(data[:262144]) > 7.2 and ext not in MEDIA_EXT and text is None:
        add("MEDIUM" if not hidden else "HIGH", rel, 0, f"Encrypted/compressed-looking binary data (entropy {entropy(data[:262144]):.1f}/8)",
            "Random-looking data can be an encrypted payload (JFrog: `.napi_cache` decrypted at runtime).", "Identify it before using the repo.")

def check_git(repo):
    """Read-only git history. Hooks, pager and fsmonitor are forced off."""
    if not os.path.isdir(os.path.join(repo, ".git")): return
    base = ["git", "--no-pager", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-c", "core.pager=cat", "-C", repo]
    def run(args):
        try: return subprocess.run(base + args, capture_output=True, text=True, timeout=30).stdout
        except Exception: return ""
    paths = [".claude", ".cursor", ".vscode", ".gemini", ".codex", ".mcp.json", ".github/init.js", "AGENTS.md", "CLAUDE.md", "package.json"]
    log = run(["log", "--all", "-n", "15", "--date=short", "--format=%h %ad %an: %s", "--"] + paths)
    if log.strip():
        add("INFO", ".git", 0, "Recent commits touching AI/editor config:\n" + "\n".join("    " + l for l in log.strip().splitlines()),
            "Shows who added the auto-run config, and when.", "Check that the authors look legitimate.")
    for l in run(["log", "--all", "-n", "500", "--format=%h %s%n%b"]).splitlines():
        for marker in MARK_HIGH + MARK_MED:
            if marker in l:
                add("HIGH" if marker in MARK_HIGH else "MEDIUM", ".git", 0, f"Commit message marker `{marker}`: {short(l, 80)}",
                    "JFrog lists this as a campaign commit marker (skip-checks:true is also used legitimately).", "Review that commit.")
    for ref in run(["for-each-ref", "--format=%(refname:short)"]).splitlines():
        if any(re.search(r"(^|/)" + re.escape(b), ref) for b in BRANCH_PREFIXES):
            add("MEDIUM", ".git", 0, f"Branch name matches JFrog pattern: {ref}", "JFrog: publisher branches `chore/ci-*`, `deps/upd-*`.", "Review that branch.")

# ---------------------------------------------------------------- main scan
def scan(repo):
    repo = os.path.abspath(repo)
    count = 0
    for root, dirs, files in os.walk(repo, followlinks=False):
        relroot = os.path.relpath(root, repo)
        for d in list(dirs):
            if d in SKIP_DIRS:
                dirs.remove(d)
                if d == "node_modules":
                    add("INFO", os.path.join(relroot, d).lstrip("./"), 0, "Committed node_modules folder (not scanned)",
                        "Pre-installed packages can hide code.", "Delete it and reinstall from a lockfile with --ignore-scripts.")
        for f in files:
            full = os.path.join(root, f)
            rel = os.path.relpath(full, repo).replace(os.sep, "/")
            low, base = rel.lower(), f.lower()
            count += 1
            if os.path.islink(full):
                tgt = os.path.realpath(full)
                if not tgt.startswith(repo + os.sep):
                    add("HIGH", rel, 0, f"Symlink points outside the repo: {os.readlink(full)}",
                        "Links like this can make tools read or overwrite files elsewhere on your computer.", "Don't open the repo.")
                continue
            try:
                size = os.path.getsize(full)
                with open(full, "rb") as fh: data = fh.read(READ_LIMIT)
            except OSError:
                continue
            text = None if b"\x00" in data[:8192] else data.decode("utf-8", errors="replace")
            hidden = any(part.startswith(".") for part in rel.split("/")[:-1])
            # --- IOC checks (from JFrog) ---
            if rel in IOC_PATHS or f in IOC_NAMES:
                add("HIGH", rel, 0, f"File name `{rel}` matches JFrog's testmetest report",
                    "JFrog found the payload at `.github/init.js` and an encrypted payload in `.napi_cache`.", "Do not open the repo.")
            if base in ("addon.node", "addon_win.node") or (base.endswith(".node") and size > 0):
                add("MEDIUM", rel, 0, "Pre-compiled native Node addon (.node)", "JFrog: native addons were used to hide the loader.", "Ask why a binary is committed.")
            if base == "binding.gyp" and text and "<!(" in text:
                add("HIGH", rel, line_of(text, "<!("), "binding.gyp runs a shell command during install (`<!(...)`)",
                    "JFrog: testmetest used this trick to run `index.js` on install without an install script.", "Never npm install this repo.")
            if size <= 25 * 1048576 and (size > BIG_FILE or os.path.splitext(base)[1] in CODE_EXT):
                h = hashlib.sha256()
                with open(full, "rb") as fh:
                    for chunk in iter(lambda: fh.read(1 << 20), b""): h.update(chunk)
                digest = h.hexdigest()
                if digest in IOC_SHA256 or digest[:8] in IOC_SHA_PREFIX:
                    add("HIGH", rel, 0, f"File hash matches JFrog IOC ({IOC_SHA256.get(digest) or IOC_SHA_PREFIX.get(digest[:8])})",
                        "This exact file was reported as malicious.", "Do not open the repo. Follow JFrog's remediation.")
            is_doc = os.path.splitext(base)[1] in (".md", ".txt", ".rst") and base not in INSTRUCTION_FILES
            if text and _sha(full) not in SELF_HASHES:
                # Docs only get the network indicators (docs often *mention* file names like .napi_cache).
                for ioc in IOC_NETWORK + ([] if is_doc else IOC_STRINGS):
                    if ioc in text:
                        add("HIGH", rel, line_of(text, ioc), f"Contains JFrog indicator `{ioc}`", "Listed as campaign infrastructure by JFrog.", "Do not open the repo.")
            # --- AI-tool / editor config ---
            data_json = load_json(text) if text and base.endswith(".json") else None
            is_ai_cfg = low.startswith(AI_DIRS) or base in (".mcp.json",) or ("mcp" in base and base.endswith(".json"))
            if text and low.startswith(".claude/") and base in ("settings.json", "settings.local.json"):
                check_claude_settings(rel, text, data_json or {})
            if text and ("mcp" in base and base.endswith(".json")):
                check_mcp(rel, text, data_json or {})
            if text and low.startswith(".vscode/"):
                check_vscode(rel, text, data_json)
            if text and low.startswith(".gemini/") and base.endswith(".json"):
                check_mcp(rel, text, data_json or {})
                if isinstance(data_json, dict) and data_json.get("hooks"):
                    check_claude_settings(rel, text, {"hooks": data_json["hooks"]})
            already = any(f[1] == rel for f in findings)   # structured check above already explained this file
            if text and is_ai_cfg and not already and not low.startswith(".github/workflows/") and os.path.splitext(base)[1] in (".json", ".toml", ".yaml", ".yml", ".sh", ".js", ""):
                check_commands(rel, text, "Command in auto-loaded AI/editor config", high_if_danger=True)
            if text and (base in INSTRUCTION_FILES or (low.startswith((".cursor/rules/", ".claude/commands/", ".claude/agents/", ".windsurf/")) and base.endswith((".md", ".mdc")))):
                check_instruction_file(rel, text)
            if text and is_ai_cfg:
                check_network(rel, text, auto=True)
            # --- install-time hooks for other ecosystems ---
            if text and base == "package.json":
                check_package_json(rel, text, data_json)
                check_network(rel, text, auto=False)
            if text and base == "composer.json" and isinstance(data_json, dict):
                for k, v in (data_json.get("scripts") or {}).items():
                    if k in COMPOSER_AUTO:
                        add("HIGH" if danger_reasons(json.dumps(v)) else "MEDIUM", rel, line_of(text, k),
                            f"Composer `{k}` runs automatically: `{short(json.dumps(v))}`", "Runs during composer install/update.", "Review before installing.")
            if text and base in ("makefile", "gnumakefile"):
                check_commands(rel, text, "Makefile command", high_if_danger=False)
            if text and (base in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml") or base.endswith((".lock",))):
                for pkg in IOC_PACKAGES:
                    if pkg in text:
                        add("HIGH", rel, line_of(text, pkg), f"Lockfile references `{pkg}` (JFrog list)", "Malicious versions exist.", "Do not install.")
            # --- obfuscation / size ---
            if base not in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml") and not base.endswith(".map"):
                check_code_blob(rel, size, text, hidden, data)
            if text and os.path.splitext(base)[1] in (".sh", ".ps1", ".bat", ".cmd") and not is_ai_cfg:
                for no, line in enumerate(text.splitlines(), 1):
                    if DANGER[0][0].search(line):
                        add("MEDIUM", rel, no, f"Script downloads and runs code: `{short(line.strip())}`", "Classic download-and-execute.", "Don't run it.")
    check_git(repo)
    return count

# ---------------------------------------------------------------- report
def report(repo, nfiles):
    by = {s: [f for f in findings if f[0] == s] for s in SEV_ORDER}
    if by["HIGH"]:
        verdict, code = "Do not open", 2
    elif by["MEDIUM"]:
        verdict, code = "Review before opening", 1
    else:
        verdict, code = "Looks clean", 0
    out = [f"# Repo pre-open scan: {os.path.basename(os.path.abspath(repo))}", "",
           f"Scanned {nfiles} files on {datetime.now():%Y-%m-%d %H:%M} (read-only; nothing was run).",
           ("Known-indicator list: iocs.json loaded (JFrog, 26 Oct 2026)." if IOCS else
            "Known-indicator list: iocs.json not found, so only the generic checks ran."), "",
           f"**Summary:** {len(by['HIGH'])} HIGH, {len(by['MEDIUM'])} MEDIUM, {len(by['INFO'])} INFO", ""]
    titles = {"HIGH": "HIGH - likely to run something on your computer, or matches known attack signs",
              "MEDIUM": "MEDIUM - worth a human look before you open the repo",
              "INFO": "INFO - for context, usually harmless"}
    for s in SEV_ORDER:
        if not by[s]: continue
        out += [f"## {titles[s]}", ""]
        for i, (_, path, line, what, why, todo) in enumerate(by[s], 1):
            loc = f"{path}:{line}" if line else path
            out += [f"{i}. **{what}**", f"   - Where: `{loc}`", f"   - Why it matters: {why}", f"   - What to do: {todo}", ""]
    out += ["---", f"## Verdict: {verdict}", ""]
    if code == 2:
        out.append("Do NOT open this folder in Claude Code, Cursor, Codex, Gemini CLI or VS Code, and do NOT run npm/pip install. "
                   "If you already opened it or installed its packages, read the 'already opened' section of STEPS.md before changing any passwords or tokens.")
    elif code == 1:
        out.append("Nothing clearly malicious, but read the MEDIUM items before opening the project in an AI tool.")
    else:
        out.append("No auto-run hooks, install scripts or obfuscated payloads found. This is a heuristic check, not a guarantee.")
    return "\n".join(out) + "\n", code

def main():
    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help"):
        print(__doc__); sys.exit(0)
    repo, outfile = args[0], "scan-report.md"
    if "--out" in args: outfile = args[args.index("--out") + 1]
    if not os.path.isdir(repo):
        print(f"Not a folder: {repo}"); sys.exit(3)
    n = scan(repo)
    text, code = report(repo, n)
    print(text)
    with open(outfile, "w", encoding="utf-8") as fh: fh.write(text)
    print(f"(Report saved to {os.path.abspath(outfile)})")
    sys.exit(code)

if __name__ == "__main__":
    main()
