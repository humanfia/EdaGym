"""Secret detection primitives that never retain or render matched values."""

from __future__ import annotations

import math
import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import PurePosixPath


@dataclass(frozen=True, slots=True)
class ContentRule:
    """A bounded byte pattern with optional entropy validation."""

    rule_id: str
    pattern: re.Pattern[bytes]
    entropy_group: str | None = None
    minimum_entropy: float | None = None

    def matches(self, data: bytes) -> bool:
        for match in self.pattern.finditer(data):
            if self.entropy_group is None:
                return True
            candidate = match.group(self.entropy_group)
            if _shannon_entropy(candidate) >= (self.minimum_entropy or 0.0):
                return True
        return False


_ASSIGNED_SECRET = re.compile(
    rb"(?i)(?:api[_-]?key|access[_-]?token|client[_-]?secret|password)"
    rb"[\"']?\s*[:=]\s*[\"']?(?P<value>[A-Za-z0-9_./+=-]{20,512})"
)

CONTENT_RULES: tuple[ContentRule, ...] = (
    ContentRule(
        "private-key-material",
        re.compile(
            rb"-----BEGIN[ \t]+(?:RSA[ \t]+|EC[ \t]+|DSA[ \t]+|OPENSSH[ \t]+)?"
            rb"PRIVATE[ \t]+KEY-----"
        ),
    ),
    ContentRule("aws-access-key", re.compile(rb"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ContentRule("github-token", re.compile(rb"\bgh[pousr]_[A-Za-z0-9]{36,255}\b")),
    ContentRule(
        "slack-token",
        re.compile(rb"\bxox[baprs]-[A-Za-z0-9-]{20,255}\b"),
    ),
    ContentRule(
        "jwt-token",
        re.compile(
            rb"\beyJ[A-Za-z0-9_-]{8,512}\.[A-Za-z0-9_-]{8,2048}\."
            rb"[A-Za-z0-9_-]{8,2048}\b"
        ),
    ),
    ContentRule(
        "provider-api-key",
        re.compile(rb"\bsk-[A-Za-z0-9_-]{20,255}\b"),
    ),
    ContentRule(
        "high-entropy-credential-assignment",
        _ASSIGNED_SECRET,
        entropy_group="value",
        minimum_entropy=3.5,
    ),
)

_EXACT_SENSITIVE_NAMES = frozenset(
    {
        ".gitleaksignore",
        ".netrc",
        ".npmrc",
        ".pypirc",
        "auth.json",
        "credentials",
        "credentials.json",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        "id_rsa",
        "license.dat",
        "license.lic",
        "service-account.json",
    }
)
_SENSITIVE_SUFFIXES = (".jks", ".key", ".kdbx", ".p12", ".pem", ".pfx")
_SENSITIVE_DIRECTORY_NAMES = frozenset({".aws", ".codex", ".ssh", "credentials"})
PRIVATE_RUNTIME_ROOTS = frozenset(
    {".edagym", ".edagym-state", "artifacts", "runs", "workspaces"}
)
_SCAN_OVERLAP = 8192


def sensitive_path_rule(path: str) -> str | None:
    """Return a fixed rule ID for a sensitive repository path, if any."""

    normalized = path.replace("\\", "/")
    parts = PurePosixPath(normalized).parts
    if not parts:
        return None
    lowered = tuple(part.casefold() for part in parts)
    basename = lowered[-1]

    if lowered[0] in PRIVATE_RUNTIME_ROOTS:
        return "runtime-state-directory"
    if any(part in _SENSITIVE_DIRECTORY_NAMES for part in lowered[:-1]):
        return "sensitive-directory"
    if basename == ".env" or basename.startswith(".env."):
        return "environment-file"
    if basename in _EXACT_SENSITIVE_NAMES:
        return "credential-filename"
    if basename.endswith(_SENSITIVE_SUFFIXES):
        return "credential-file-extension"
    return None


def sensitive_tree_entry_rule(name: str, *, is_directory: bool) -> str | None:
    """Classify one Git tree entry without requiring its parent path."""

    lowered = name.casefold()
    if is_directory and lowered in _SENSITIVE_DIRECTORY_NAMES:
        return "sensitive-directory"
    rule = sensitive_path_rule(name)
    return None if rule == "runtime-state-directory" else rule


def sensitive_root_tree_entry_rule(name: str, *, is_directory: bool) -> str | None:
    """Classify a repository-root tree entry that owns private runtime state."""

    if is_directory and name.casefold() in PRIVATE_RUNTIME_ROOTS:
        return "runtime-state-directory"
    return None


def matching_content_rules(chunks: Iterable[bytes]) -> frozenset[str]:
    """Scan a byte stream and return rule IDs without retaining matched material."""

    matched: set[str] = set()
    tail = b""
    for chunk in chunks:
        if not chunk:
            continue
        window = tail + chunk
        for rule in CONTENT_RULES:
            if rule.rule_id not in matched and rule.matches(window):
                matched.add(rule.rule_id)
        tail = window[-_SCAN_OVERLAP:]
    return frozenset(matched)


def _shannon_entropy(value: bytes) -> float:
    if not value:
        return 0.0
    counts: dict[int, int] = {}
    for byte in value:
        counts[byte] = counts.get(byte, 0) + 1
    length = len(value)
    return -sum(
        (count / length) * math.log2(count / length) for count in counts.values()
    )
