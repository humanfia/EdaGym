"""Secret detection primitives that never retain or render matched values."""

from __future__ import annotations

import math
import re
from collections.abc import Iterable, Sequence
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

RESTRICTED_CONTENT_RULES: tuple[ContentRule, ...] = (
    ContentRule(
        "host-path",
        re.compile(
            rb"(?<![A-Za-z0-9_.-])/(?:data[0-9]*|eda|etc|fast|home|mnt|net|nfs|"
            rb"opt|proj|project|root|run|scratch|tmp|tools|usr|var|work)/"
            rb"[^\x00\s\"'<>]{1,512}"
        ),
    ),
    ContentRule(
        "network-endpoint",
        re.compile(
            rb"(?i)\b(?:grpc|grpcs|http|https|ssh|tcp|udp)://"
            rb"[^\x00\s\"'<>]{1,512}"
        ),
    ),
    ContentRule(
        "network-address",
        re.compile(
            rb"(?i)\b(?:localhost|"
            rb"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
            rb"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+|"
            rb"(?:[0-9]{1,3}\.){3}[0-9]{1,3}):[0-9]{1,5}\b"
        ),
    ),
    ContentRule(
        "license-route",
        re.compile(
            rb"(?i)(?:\b(?:[A-Z][A-Z0-9_]*(?:_LIC|_LICENSE)[A-Z0-9_]*|"
            rb"LICENSE(?:_[A-Z0-9]+)*)"
            rb"[\"']?\s*[:=]\s*[\"']?[^\x00\s,\"'}]{1,512}|"
            rb"\b[0-9]{1,5}@[A-Za-z0-9][A-Za-z0-9.-]{0,253}\b)"
        ),
    ),
    ContentRule(
        "pdk-library-identity",
        re.compile(
            rb"(?i)\b(?:liberty|library|pdk|standard[ _-]?cell|technology)"
            rb"(?:[ _-]?name)?[\"']?\s*[:=]\s*[\"']?"
            rb"[A-Za-z0-9_./+-]{2,256}"
        ),
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
_SENSITIVE_DIRECTORY_NAMES = frozenset(
    {".aws", ".claude", ".codex", ".ssh", "credentials", "secrets"}
)
PRIVATE_RUNTIME_ROOTS = frozenset(
    {
        ".benchmarks",
        ".edagym",
        ".edagym-state",
        ".xil",
        "artifacts",
        "runs",
        "task_families",
        "workspaces",
    }
)
_SCAN_OVERLAP = 8192


class ContentRuleScanner:
    """Incrementally classify bounded sensitive patterns without retaining matches."""

    __slots__ = ("_matched", "_rules", "_tail")

    def __init__(self, rules: Sequence[ContentRule]) -> None:
        self._rules = tuple(rules)
        self._matched: set[str] = set()
        self._tail = b""

    def update(self, chunk: bytes) -> None:
        if not chunk:
            return
        window = self._tail + chunk
        for rule in self._rules:
            if rule.rule_id not in self._matched and rule.matches(window):
                self._matched.add(rule.rule_id)
        self._tail = window[-_SCAN_OVERLAP:]

    @property
    def matched_rule_ids(self) -> frozenset[str]:
        return frozenset(self._matched)


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

    scanner = ContentRuleScanner(CONTENT_RULES)
    for chunk in chunks:
        scanner.update(chunk)
    return scanner.matched_rule_ids


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
