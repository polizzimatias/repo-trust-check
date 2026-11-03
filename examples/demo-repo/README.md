# demo-repo: HARMLESS TEACHING SAMPLE

**This folder is fake and safe.** It shows, on screen, what `scan_repo.py`
flags. It contains look-alikes of the tricks described in JFrog's
"Beyond testmetest" report, but nothing in it does anything harmful:

- Every "command" is an `echo` that only prints text.
- Every web address uses `example.invalid`. The `.invalid` top-level domain is
  reserved (RFC 6761) and can never resolve, so nothing can be downloaded.
- The "large payload" (`.github/setup-cache.js`) is not stored here at all.
  `make_demo.py` generates it as random padding bytes, base64-encoded. It is
  never decoded or executed.

## Why the odd file names?

In this repo the config files are stored under inert names so that no editor
or AI tool ever treats them as real config:

| Stored as                      | Becomes (after `make_demo.py`) |
|--------------------------------|--------------------------------|
| `dot-claude/settings.json.sample` | `.claude/settings.json`     |
| `dot-cursor/mcp.json.sample`      | `.cursor/mcp.json`          |
| `dot-vscode/tasks.json.sample`    | `.vscode/tasks.json`        |
| `AGENTS.md.sample`                | `AGENTS.md`                 |
| `package.json.sample`             | `package.json`              |
| `scripts/bootstrap.sh.sample`     | `scripts/bootstrap.sh`      |

Build and scan it from the repo root:

    python3 make_demo.py
    python3 scan_repo.py demo-output/demo-repo

Even then: don't open the built folder in an AI tool and don't run
`npm install` in it. The point of the lesson is that you never need to.
