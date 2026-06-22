"""Bounded base64 / hex decoding for obfuscation analysis (§4.5, §6.4).

Attackers hide payloads (reverse shells, ``curl|bash``) inside encoded blobs. We
decode and recurse **one level** so the decoded content can be re-scanned, but with
hard caps on output size and recursion depth so a crafted input can't bomb us.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass

import re2

from analyzer.config import AnalyzerConfig

_B64_RE = re2.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_HEX_RE = re2.compile(r"(?:[0-9a-fA-F]{2}){16,}")
_MIN_PRINTABLE_RATIO = 0.85


@dataclass
class DecodedBlob:
    encoding: str  # "base64" | "hex"
    text: str
    source_snippet: str
    depth: int


def _printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    good = sum(1 for c in s if c.isprintable() or c in "\t\n\r ")
    return good / len(s)


def _try_decode(encoding: str, candidate: str, config: AnalyzerConfig) -> str | None:
    try:
        if encoding == "base64":
            raw = base64.b64decode(candidate, validate=True)
        else:
            raw = bytes.fromhex(candidate)
    except (ValueError, base64.binascii.Error):  # type: ignore[attr-defined]
        return None
    raw = raw[: config.decode_max_output_bytes]
    text = raw.decode("utf-8", errors="replace")
    if len(text) < 4 or _printable_ratio(text) < _MIN_PRINTABLE_RATIO:
        return None
    return text


def _candidates(text: str) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    for m in _B64_RE.finditer(text):
        found.append(("base64", str(m.group(0))))
    for m in _HEX_RE.finditer(text):
        found.append(("hex", str(m.group(0))))
    return found


def find_and_decode(text: str, config: AnalyzerConfig) -> list[DecodedBlob]:
    results: list[DecodedBlob] = []
    _decode_recursive(text, config, 1, results)
    return results


def _decode_recursive(
    text: str, config: AnalyzerConfig, depth: int, results: list[DecodedBlob]
) -> None:
    if depth > config.decode_max_depth or len(results) >= config.decode_max_blobs:
        return
    for encoding, candidate in _candidates(text):
        if len(results) >= config.decode_max_blobs:  # cap total blobs — anti finding-explosion
            return
        decoded = _try_decode(encoding, candidate, config)
        if decoded is None:
            continue
        results.append(
            DecodedBlob(
                encoding=encoding,
                text=decoded,
                source_snippet=candidate[:80],
                depth=depth,
            )
        )
        _decode_recursive(decoded, config, depth + 1, results)
