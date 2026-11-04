"""Tests for the scanner, the skill package and the optional Claude Code hook.

Run from the repo root:  python3 -m unittest discover -s tests -v
Standard library only. Uses the harmless fixtures in examples/ (built into a temp folder),
never a real malicious repo, and never needs the network.
"""
import json, os, re, subprocess, sys, tempfile, unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKILL = os.path.join(ROOT, "skills", "repo-trust-check")
CHECK = os.path.join(SKILL, "check_repo.py")
GUARD = os.path.join(ROOT, "plugins", "repo-trust-check-hook", "hooks", "clone_guard.py")
PY = sys.executable
GIT_ENV = dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.com",
               GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.com")


def read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, stdin=subprocess.DEVNULL, **kw)


class Fixtures:
    """Build demo-repo / clean-repo once with make_demo.py and turn each into a local git repo."""
    tmp = None

    @classmethod
    def get(cls):
        if cls.tmp is None:
            cls._td = tempfile.TemporaryDirectory(prefix="rtc-test-")
            cls.tmp = cls._td.name
            out = os.path.join(cls.tmp, "fixtures")
            r = run([PY, os.path.join(ROOT, "make_demo.py"), out])
            assert r.returncode == 0, r.stdout + r.stderr
            for name in ("demo-repo", "clean-repo"):
                d = os.path.join(out, name)
                for c in (["git", "init", "-q"], ["git", "-c", "core.hooksPath=" + os.devnull, "add", "-A"],
                          ["git", "-c", "core.hooksPath=" + os.devnull, "commit", "-qm", "fixture"]):
                    r = run(c, cwd=d, env=GIT_ENV)
                    assert r.returncode == 0, r.stderr
        return cls.tmp


def file_url(path):
    return "file://" + path.replace(os.sep, "/") if path.startswith("/") else "file:///" + path.replace(os.sep, "/")


class TestSync(unittest.TestCase):
    def test_skill_copies_match_root(self):
        r = run([PY, os.path.join(ROOT, "tools", "sync_skill.py"), "--check"])
        self.assertEqual(r.returncode, 0, r.stdout)


class TestSkillPackage(unittest.TestCase):
    def frontmatter(self):
        text = read(os.path.join(SKILL, "SKILL.md"))
        m = re.match(r"---\n(.*?)\n---\n", text, re.S)
        self.assertIsNotNone(m, "SKILL.md needs YAML frontmatter")
        return dict(re.findall(r"^([\w-]+):\s*(.*)$", m.group(1), re.M))

    def test_agent_skills_spec_basics(self):
        fm = self.frontmatter()
        self.assertEqual(fm["name"], os.path.basename(SKILL))           # must match the folder name
        self.assertRegex(fm["name"], r"^[a-z0-9]+(-[a-z0-9]+)*$")
        self.assertLessEqual(len(fm["name"]), 64)
        self.assertTrue(0 < len(fm["description"]) <= 1024)
        for word in ("GitHub", "GitLab", "clone", "download", "install"):
            self.assertIn(word, fm["description"])

    def test_bundled_files_present(self):
        for f in ("SKILL.md", "check_repo.py", "scan_repo.py", "iocs.json"):
            self.assertTrue(os.path.isfile(os.path.join(SKILL, f)), f)

    def test_marketplace_points_at_real_plugins(self):
        mk = json.loads(read(os.path.join(ROOT, ".claude-plugin", "marketplace.json")))
        for p in mk["plugins"]:
            src = os.path.join(ROOT, p["source"])
            manifest = json.loads(read(os.path.join(src, ".claude-plugin", "plugin.json")))
            self.assertEqual(manifest["name"], p["name"])
            self.assertFalse(".." in p["source"])


class TestScanner(unittest.TestCase):
    def scan(self, name):
        tmp = Fixtures.get()
        return run([PY, os.path.join(SKILL, "scan_repo.py"), os.path.join(tmp, "fixtures", name),
                    "--out", os.path.join(tmp, name + ".md")])

    def test_demo_repo_is_do_not_open(self):
        r = self.scan("demo-repo")
        self.assertEqual(r.returncode, 2, r.stdout[-2000:])
        self.assertIn("## Verdict: Do not open", r.stdout)

    def test_clean_repo_is_clean(self):
        r = self.scan("clean-repo")
        self.assertEqual(r.returncode, 0, r.stdout[-2000:])
        self.assertIn("## Verdict: Looks clean", r.stdout)


class TestCheckRepo(unittest.TestCase):
    def check(self, *args, quarantine):
        return run([PY, CHECK, *args, "--quarantine", quarantine])

    def test_clones_into_quarantine_and_blocks_bad_repo(self):
        tmp = Fixtures.get()
        q = os.path.join(tmp, "q1")
        r = self.check(file_url(os.path.join(tmp, "fixtures", "demo-repo")), quarantine=q)
        self.assertEqual(r.returncode, 2, r.stdout[-2000:] + r.stderr)
        dest = os.path.join(q, "demo-repo")
        self.assertIn(f"RESULT: Do not open | folder: {dest}", r.stdout)
        self.assertTrue(os.path.isfile(dest + ".scan-report.md"))
        hooks = run(["git", "-C", dest, "config", "--get", "core.hooksPath"]).stdout.strip()
        self.assertEqual(hooks, os.devnull)                            # later git commands skip repo hooks too
        self.assertFalse(os.path.exists(os.path.join(dest, "node_modules")))

    def test_clean_repo_and_no_overwrite(self):
        tmp = Fixtures.get()
        q = os.path.join(tmp, "q2")
        url = file_url(os.path.join(tmp, "fixtures", "clean-repo"))
        first = self.check(url, quarantine=q)
        second = self.check(url, quarantine=q)
        self.assertEqual(first.returncode, 0, first.stdout[-2000:] + first.stderr)
        self.assertIn("RESULT: Looks clean", first.stdout)
        self.assertIn(os.path.join(q, "clean-repo-2"), second.stdout)   # never overwrites an earlier copy

    def test_scans_existing_folder_in_place(self):
        tmp = Fixtures.get()
        r = self.check(os.path.join(tmp, "fixtures", "clean-repo"), quarantine=os.path.join(tmp, "q3"))
        self.assertEqual(r.returncode, 0)
        self.assertIn("Scanning the folder where it is", r.stdout)

    def test_rejects_things_that_are_not_repo_links(self):
        q = os.path.join(Fixtures.get(), "q4")
        for bad in ("ext::sh -c touch% /tmp/x", "--upload-pack=touch /tmp/x", "not a url"):
            r = self.check(bad, quarantine=q)
            self.assertEqual(r.returncode, 3, bad)
            self.assertIn("Could not check", r.stdout)

    def test_github_page_links_become_clone_urls(self):
        sys.dont_write_bytecode = True
        sys.path.insert(0, SKILL)
        try:
            import check_repo
        finally:
            sys.path.pop(0)
        self.assertEqual(check_repo.normalize("https://github.com/o/r/tree/main/src"), "https://github.com/o/r")
        self.assertEqual(check_repo.normalize("https://gitlab.com/g/sub/r/-/tree/main"), "https://gitlab.com/g/sub/r")
        self.assertEqual(check_repo.repo_name("https://github.com/o/My Repo.git"), "My-Repo")


class TestCloneGuardHook(unittest.TestCase):
    def decide(self, command, env=None):
        r = subprocess.run(
            [PY, GUARD], input=json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash",
                                           "tool_input": {"command": command}}),
            capture_output=True, text=True, env=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        if not r.stdout.strip():
            return "allow"
        return json.loads(r.stdout)["hookSpecificOutput"]["permissionDecision"]

    def test_blocks_plain_clones(self):
        for c in ("git clone https://github.com/a/b", "cd ~ && git -c http.proxy=x clone https://gitlab.com/a/b x",
                  "gh repo clone a/b", "npx degit a/b app",
                  "curl -L https://github.com/a/b/archive/refs/heads/main.zip -o b.zip"):
            self.assertEqual(self.decide(c), "deny", c)

    def test_allows_other_commands_and_the_safety_check(self):
        for c in ("ls -la", "git status", "git log --oneline", "python3 /x/check_repo.py https://github.com/a/b",
                  "GIT_LFS_SKIP_SMUDGE=1 git clone --no-recurse-submodules https://github.com/a/b ~/repo-quarantine/b"):
            self.assertEqual(self.decide(c), "allow", c)

    def test_can_be_switched_off(self):
        env = dict(os.environ, REPO_TRUST_CHECK_HOOK="off")
        self.assertEqual(self.decide("git clone https://github.com/a/b", env=env), "allow")


if __name__ == "__main__":
    unittest.main()
