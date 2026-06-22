"""Supply-chain tests (M4, §4.6). OSV is dependency-injected so tests stay offline."""

from __future__ import annotations

import io
import zipfile

from analyzer.config import DEFAULT_CONFIG
from analyzer.discovery import discover
from analyzer.ingest.archive import ingest_zip
from analyzer.layers.supply_chain import (
    Dependency,
    analyze_supply_chain,
    dep_key,
    parse_dependencies,
)
from analyzer.models import Category, Severity


def _zip(entries: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return buf.getvalue()


def _bundle(entries):
    return ingest_zip(_zip(entries), DEFAULT_CONFIG)


def test_parses_requirements_txt():
    with _bundle({"SKILL.md": b"---\nname: x\n---\nb", "requirements.txt": b"requests==2.19.0\nflask>=1.0\n"}) as b:
        disc = discover(b, DEFAULT_CONFIG)
        deps = parse_dependencies(b, disc)
        names = {d.name: d for d in deps}
        assert names["requests"].version == "2.19.0"
        assert names["requests"].ecosystem == "PyPI"


def test_parses_package_json():
    pkg = b'{"dependencies": {"lodash": "4.17.4", "react": "^18.0.0"}}'
    with _bundle({"SKILL.md": b"---\nname: x\n---\nb", "package.json": pkg}) as b:
        disc = discover(b, DEFAULT_CONFIG)
        deps = parse_dependencies(b, disc)
        names = {d.name: d for d in deps}
        assert names["lodash"].version == "4.17.4"
        assert names["lodash"].ecosystem == "npm"


def test_known_vuln_reports_osv_advisory():
    with _bundle({"SKILL.md": b"---\nname: x\n---\nb", "requirements.txt": b"requests==2.19.0\n"}) as b:
        disc = discover(b, DEFAULT_CONFIG)

        def fake_osv(deps, config):
            return {dep_key(d): ["GHSA-xxxx-vuln-0001"] for d in deps}

        findings = analyze_supply_chain(b, disc, DEFAULT_CONFIG, osv_query=fake_osv)
        hit = next(f for f in findings if f.category is Category.SUPPLY_CHAIN and "GHSA-xxxx" in f.evidence)
        assert hit.severity is Severity.HIGH


def test_offline_degrades_gracefully():
    with _bundle({"SKILL.md": b"---\nname: x\n---\nb", "requirements.txt": b"requests==2.19.0\n"}) as b:
        disc = discover(b, DEFAULT_CONFIG)

        def broken_osv(deps, config):
            raise ConnectionError("offline")

        findings = analyze_supply_chain(b, disc, DEFAULT_CONFIG, osv_query=broken_osv)
        # no crash; an Info note that the check was skipped
        assert any(f.severity is Severity.INFO and "OSV" in f.risk for f in findings)


def test_clean_deps_no_high_finding():
    with _bundle({"SKILL.md": b"---\nname: x\n---\nb", "requirements.txt": b"requests==2.31.0\n"}) as b:
        disc = discover(b, DEFAULT_CONFIG)
        findings = analyze_supply_chain(b, disc, DEFAULT_CONFIG, osv_query=lambda deps, config: {})
        assert not any(f.category is Category.SUPPLY_CHAIN and f.severity is Severity.HIGH for f in findings)


def test_mutable_ref_is_flagged():
    reqs = b"git+https://github.com/evil/pkg@main#egg=pkg\n"
    with _bundle({"SKILL.md": b"---\nname: x\n---\nb", "requirements.txt": reqs}) as b:
        disc = discover(b, DEFAULT_CONFIG)
        findings = analyze_supply_chain(b, disc, DEFAULT_CONFIG, osv_query=lambda deps, config: {})
        assert any(f.id.startswith("supply.mutable_ref") for f in findings)


def test_dep_key_roundtrip():
    d = Dependency(name="requests", version="2.19.0", ecosystem="PyPI", file="requirements.txt", line=1)
    assert dep_key(d) == "PyPI:requests:2.19.0"
