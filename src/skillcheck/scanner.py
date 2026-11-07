"""Bounded, deterministic text inspection. Scanned text is always data."""

import os
import re
import stat
import unicodedata
from dataclasses import asdict, dataclass, field
from pathlib import Path

MAX_BYTES = 1024 * 1024
SKIP_DIRS = {".git", ".hg", ".svn", ".venv", "venv", "env", "__pycache__",
             ".pytest_cache", ".mypy_cache", ".ruff_cache", "node_modules"}
RULES = {
    "SC001": ("high", "remote download piped to shell",
              "A curl/wget HTTP(S) download is piped directly into a shell."),
    "SC002": ("medium", "possible data upload",
              "An upload command references local data or nearby credential material; review intent."),
    "SC003": ("medium", "invisible or control character",
              "Formatting, bidi, or unexpected control characters can conceal text or alter display."),
    "SC004": ("medium", "possible prompt-injection instruction",
              "Text attempts to override instructions, conceal actions, or impersonate a system message."),
}
PIPE = re.compile(r"\b(?:curl|wget)\b[^\n|]{0,4096}https?://[^\n|]{0,4096}\|\s*(?:/bin/)?(?:bash|sh|zsh|dash)\b", re.I)
UPLOAD = re.compile(r"\b(?:curl|wget)\b|\brequests\.(?:post|put)\s*\(", re.I)
LOCAL_DATA = re.compile(r"(?:--(?:data(?:-binary|-raw)?|upload-file|post-file)|-[dTF])(?:[ \t]*=[ \t]*|[ \t]+)?[\"']?@|--(?:upload-file|post-file)\b|(?:^|\s)-T\s+|\b(?:data|files)\s*=\s*open\s*\(", re.I)
CREDENTIAL = re.compile(r"\b(?:api[_-]?key|access[_-]?token|secret|password|authorization)\b|\.ssh/|\.env\b", re.I)
SEND_DATA = re.compile(r"--data\b|--data-binary\b|(?:^|\s)-d\s|\b(?:data|json|files)\s*=", re.I)
INJECTION = re.compile(r"\b(?:ignore|disregard|override)\s+(?:(?:all|any|the|your)\s+){0,3}(?:previous|prior|system|developer|safety)\s+(?:instructions?|prompts?|rules?)\b|\bdo\s+not\s+(?:tell|inform|notify)\s+(?:the\s+)?user\b|<\|(?:im_start|start_header_id)\|>\s*system\b|\byou\s+are\s+now\s+(?:the\s+)?system\b", re.I)


def safe(text: str, limit: int = 180) -> str:
    """Escape terminal controls, bidi/format characters and lone surrogates."""
    result = []
    for char in text[:limit]:
        if unicodedata.category(char).startswith("C") or char in "\u2028\u2029":
            code = ord(char)
            result.append(f"\\u{code:04x}" if code <= 0xffff else f"\\U{code:08x}")
        else:
            result.append(char)
    return "".join(result) + ("…" if len(text) > limit else "")


@dataclass
class Report:
    scanned_files: int = 0
    findings: list = field(default_factory=list)
    skipped: list = field(default_factory=list)
    errors: list = field(default_factory=list)

    @property
    def exit_code(self):
        return 2 if self.errors else int(bool(self.findings))

    def as_dict(self):
        return {**asdict(self), "skipped_count": len(self.skipped), "exit_code": self.exit_code}


def inspect_text(text, path):
    lines = text.split("\n")
    hits = set()
    # Normalize shell continuation only, preserving newlines for source locations.
    logical = text.replace("\\\r\n", " \r\n").replace("\\\n", " \n")
    # A continuation before the pipe needs joining; keep an offset->source-line map.
    joined, source_lines = [], []
    for number, line in enumerate(logical.split("\n"), 1):
        original = lines[number - 1]
        joined.append(line + (" " if original.rstrip("\r").endswith("\\") else "\n"))
        source_lines.extend([number] * (len(line) + 1))
    for match in PIPE.finditer("".join(joined)):
        hits.add((source_lines[match.start()], "SC001"))
    for index, line in enumerate(lines):
        number = index + 1
        if UPLOAD.search(line):
            nearby = "\n".join(lines[max(0, index - 2):index + 3])
            if LOCAL_DATA.search(line) or (SEND_DATA.search(line) and CREDENTIAL.search(nearby)):
                hits.add((number, "SC002"))
        if any((unicodedata.category(c) in {"Cf", "Cc", "Cs"} and c != "\t")
               or c in "\u2028\u2029" for c in line.removesuffix("\r")):
            hits.add((number, "SC003"))
        if INJECTION.search(line):
            hits.add((number, "SC004"))
    return [{"file": path, "line": number, "rule_id": rule,
             "severity": RULES[rule][0], "title": RULES[rule][1],
             "rationale": RULES[rule][2], "context": safe(lines[number - 1])}
            for number, rule in sorted(hits)]


def scan(path):
    report = Report()
    root = Path(path)

    def skipped(name, reason):
        report.skipped.append({"file": name, "reason": reason})

    def error(name, exc):
        report.errors.append({"file": name, "error": str(exc)})

    pending = [(root, root.name)]
    while pending:
        entry, name = pending.pop()
        try:
            info = entry.lstat()
            if stat.S_ISLNK(info.st_mode):
                skipped(name, "symlink (never followed)")
            elif stat.S_ISDIR(info.st_mode):
                if entry == root:
                    name = "."
                if entry.name in SKIP_DIRS:
                    skipped(name, "excluded directory (contents not counted)")
                    continue
                # Check every child with lstat rather than following directory links.
                for child in sorted(entry.iterdir(), key=lambda item: item.name, reverse=True):
                    pending.append((child, child.name if name == "." else name + "/" + child.name))
            elif stat.S_ISREG(info.st_mode):
                if info.st_size > MAX_BYTES:
                    skipped(name, "over 1 MiB limit")
                    continue
                flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
                fd = os.open(entry, flags)
                with os.fdopen(fd, "rb") as stream:
                    if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                        raise OSError("file changed type during scan")
                    raw = stream.read(MAX_BYTES + 1)
                if len(raw) > MAX_BYTES:
                    skipped(name, "over 1 MiB limit")
                    continue
                if b"\0" in raw:
                    skipped(name, "binary (NUL byte)")
                    continue
                try:
                    text = raw.decode("utf-8")
                except UnicodeDecodeError:
                    skipped(name, "non-UTF-8 or binary")
                    continue
                report.scanned_files += 1
                report.findings.extend(inspect_text(text, name))
            else:
                skipped(name, "special file (not read)")
        except (OSError, ValueError) as exc:
            error(name, exc)

    return report
