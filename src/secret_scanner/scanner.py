from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

from .rules import PII_RULES, RULES, Rule


DEFAULT_IGNORED_DIRS = {
    ".git",
    ".hg",
    ".mypy_cache",
    ".pytest_cache",
    ".venv",
    "__pycache__",
    "node_modules",
}

DEFAULT_EXTENSIONS = {
    ".env",
    ".ini",
    ".json",
    ".md",
    ".properties",
    ".py",
    ".sh",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    rule: str
    severity: str
    value: str
    category: str = "secret"

    def to_dict(self) -> dict:
        return asdict(self)


def scan_path(
    target: str | Path,
    *,
    ignored_dirs: Iterable[str] = DEFAULT_IGNORED_DIRS,
    extensions: Iterable[str] = DEFAULT_EXTENSIONS,
    include_pii: bool = False,
) -> list[Finding]:
    target_path = Path(target)
    if not target_path.exists():
        raise FileNotFoundError(f"path does not exist: {target_path}")

    allowed_extensions = set(extensions)
    ignored = set(ignored_dirs)
    files = [target_path] if target_path.is_file() else _iter_files(target_path, ignored, allowed_extensions)

    rules = RULES + PII_RULES if include_pii else RULES
    findings: list[Finding] = []
    for file_path in files:
        findings.extend(scan_file(file_path, rules=rules))
    return findings


def scan_file(path: str | Path, *, rules: Iterable[Rule] = RULES) -> list[Finding]:
    file_path = Path(path)
    rules = list(rules)
    findings: list[Finding] = []

    try:
        lines = file_path.read_text(encoding="utf-8").splitlines()
    except UnicodeDecodeError:
        return []

    for line_number, line in enumerate(lines, start=1):
        taken: list[tuple[int, int]] = []
        for rule in rules:
            for match in rule.pattern.finditer(line):
                if rule.validator is not None and not rule.validator(match):
                    continue
                start, end = match.span(rule.secret_group)
                # One secret, one finding: skip matches that overlap text an
                # earlier (more specific) rule already reported on this line.
                if any(start < e and s < end for s, e in taken):
                    continue
                taken.append((start, end))
                findings.append(
                    Finding(
                        path=str(file_path),
                        line=line_number,
                        rule=rule.name,
                        severity=rule.severity,
                        value=mask_secret(match.group(rule.secret_group)),
                        category=rule.category,
                    )
                )

    return findings


def mask_secret(secret: str) -> str:
    if len(secret) <= 8:
        return "*" * len(secret)
    return f"{secret[:4]}{'*' * max(len(secret) - 8, 4)}{secret[-4:]}"


def _iter_files(root: Path, ignored_dirs: set[str], extensions: set[str]) -> list[Path]:
    files: list[Path] = []
    for path in root.rglob("*"):
        if any(part in ignored_dirs for part in path.parts):
            continue
        if path.is_file() and (path.suffix in extensions or path.name.startswith(".env")):
            files.append(path)
    return sorted(files)

