from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import Callable, Optional


@dataclass(frozen=True)
class Rule:
    name: str
    severity: str
    pattern: re.Pattern[str]
    secret_group: str = "secret"
    category: str = "secret"
    # Optional extra check on the matched text. Returning False drops the match.
    validator: Optional[Callable[[re.Match[str]], bool]] = None


def shannon_entropy(text: str) -> float:
    """Bits per character of the string's own character distribution."""
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


# A 40-char git SHA is hex, so its entropy can never go above 4.0 bits/char.
# Random base64 or base62 tokens of 32+ chars usually land between 4.5 and 5.5.
ENTROPY_THRESHOLD = 4.0


def _high_entropy(match: re.Match[str]) -> bool:
    token = match.group("secret")
    # Long identifiers like test_scans_directories_and_ignores_binary_files
    # match the character class too. Real tokens almost always mix digits,
    # upper case, and lower case, so require all three.
    if not (any(c.isdigit() for c in token) and any(c.isupper() for c in token) and any(c.islower() for c in token)):
        return False
    return shannon_entropy(token) > ENTROPY_THRESHOLD


# Values that point at a secret instead of containing one.
_REFERENCE_PREFIXES = (
    "os.",
    "getenv",
    "process.env",
    "$",
    "<",
    "{",
    "None",
    "null",
    "True",
    "False",
)
# Placeholders people put in docs, like "your-api-key-here".
_PLACEHOLDER_HINTS = ("your-", "your_", "-here", "_here", "placeholder", "changeme", "xxxx", "...")
_FUNCTION_CALL = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*\(")


def _literal_value(match: re.Match[str]) -> bool:
    value = match.group("value").strip("'\"")
    if len(value) < 4:
        return False
    if value.startswith(_REFERENCE_PREFIXES):
        return False
    if any(hint in value.lower() for hint in _PLACEHOLDER_HINTS):
        return False
    return not _FUNCTION_CALL.match(value)


def _luhn_ok(match: re.Match[str]) -> bool:
    digits = [int(c) for c in match.group("secret") if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for index, digit in enumerate(reversed(digits)):
        if index % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


_PLACEHOLDER_EMAIL_DOMAINS = (
    "example.com",
    "example.org",
    "example.net",
    "test.com",
    "localhost",
    "users.noreply.github.com",
)


def _real_looking_email(match: re.Match[str]) -> bool:
    domain = match.group("secret").rsplit("@", 1)[-1].lower()
    return not domain.endswith(_PLACEHOLDER_EMAIL_DOMAINS)


# Order matters: when two rules match overlapping text on the same line, only
# the first one is reported. Specific HIGH rules go first, the generic
# assignment and entropy rules go last.
RULES = [
    Rule(
        name="AWS access key",
        severity="HIGH",
        pattern=re.compile(r"(?P<secret>AKIA[0-9A-Z]{16})"),
    ),
    Rule(
        name="GitHub token",
        severity="HIGH",
        pattern=re.compile(r"(?P<secret>gh[pousr]_[A-Za-z0-9_]{20,})"),
    ),
    Rule(
        name="Google API key",
        severity="HIGH",
        pattern=re.compile(r"(?P<secret>AIza[0-9A-Za-z_-]{35})"),
    ),
    Rule(
        name="Slack token",
        severity="HIGH",
        pattern=re.compile(r"(?P<secret>xox[baprs]-[A-Za-z0-9-]{20,})"),
    ),
    Rule(
        name="Private key block",
        severity="HIGH",
        pattern=re.compile(r"(?P<secret>-----BEGIN [A-Z ]*PRIVATE KEY-----)"),
    ),
    Rule(
        name="Environment assignment with secret-like name",
        severity="MEDIUM",
        # The name can have a prefix or suffix (GEMINI_API_KEY, DB_PASSWORD,
        # SECRET_KEY). v0.1 required the keyword at a word boundary, so any
        # prefixed name slipped through.
        pattern=re.compile(
            r"(?i)(?P<secret>\b[A-Za-z0-9_]*?(?:api[_-]?key|secret|passw(?:or)?d|token)[A-Za-z0-9_]*"
            r"\s*=\s*(?P<value>['\"]?[^'\"\s#]+))"
        ),
        validator=_literal_value,
    ),
    Rule(
        name="High entropy token",
        severity="LOW",
        pattern=re.compile(r"(?P<secret>(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{32,}={0,2})"),
        validator=_high_entropy,
    ),
]


# Personal data rules. Off by default, turned on with --pii.
PII_RULES = [
    Rule(
        name="US Social Security number",
        severity="HIGH",
        category="pii",
        pattern=re.compile(r"\b(?P<secret>(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4})\b"),
    ),
    Rule(
        name="Payment card number",
        severity="HIGH",
        category="pii",
        pattern=re.compile(r"(?<![\d-])(?P<secret>\d(?:[ -]?\d){12,18})(?![\d-])"),
        validator=_luhn_ok,
    ),
    Rule(
        name="Email address",
        severity="LOW",
        category="pii",
        pattern=re.compile(r"(?P<secret>[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})"),
        validator=_real_looking_email,
    ),
]
