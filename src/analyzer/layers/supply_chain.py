"""Supply-chain analysis (§4.6).

Parses dependency manifests, queries OSV.dev for known-vuln pinned versions, and
flags mutable refs and likely typosquats. The OSV query is injected so it can be
faked in tests; a network failure degrades gracefully to an Info note.
"""

from __future__ import annotations

import json
import tomllib
from collections.abc import Callable
from dataclasses import dataclass

import httpx
import re2

from analyzer.bundle import Bundle
from analyzer.config import AnalyzerConfig
from analyzer.discovery import Discovery
from analyzer.findings import make_finding
from analyzer.models import Category, Confidence, ComponentType, Finding, Severity, SourceLayer

_REQ_LINE = re2.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*(==|>=|<=|~=|>|<)\s*([A-Za-z0-9_.\-]+)")
_MUTABLE_REF = re2.compile(
    r"(?i)(git\+https?://[^\s]+@(main|master|head|develop|trunk)\b"
    r"|(curl|wget)\s+https?://[^\s]*/(main|master|HEAD)/)"
)

_POPULAR = {
    "PyPI": {"requests", "numpy", "pandas", "flask", "django", "urllib3", "setuptools", "pyyaml", "cryptography", "boto3"},
    "npm": {"react", "lodash", "express", "axios", "chalk", "commander", "debug", "moment"},
}

OsvQuery = Callable[[list["Dependency"], AnalyzerConfig], dict[str, list[str]]]


@dataclass
class Dependency:
    name: str
    version: str | None
    ecosystem: str  # "PyPI" | "npm"
    file: str
    line: int


def dep_key(dep: Dependency) -> str:
    return f"{dep.ecosystem}:{dep.name}:{dep.version}"


# --- parsing ---------------------------------------------------------------------------------


def parse_dependencies(bundle: Bundle, discovery: Discovery) -> list[Dependency]:
    deps: list[Dependency] = []
    for comp in discovery.components:
        name = comp.path.rsplit("/", 1)[-1]
        try:
            text = bundle.read_text(comp.path)
        except (OSError, ValueError):
            continue
        if name == "requirements.txt":
            deps += _parse_requirements(text, comp.path)
        elif name == "pyproject.toml":
            deps += _parse_pyproject(text, comp.path)
        elif name == "package.json":
            deps += _parse_package_json(text, comp.path)
    return deps


def _parse_requirements(text: str, file: str) -> list[Dependency]:
    deps: list[Dependency] = []
    for i, line in enumerate(text.splitlines(), start=1):
        if line.strip().startswith("#") or not line.strip():
            continue
        m = _REQ_LINE.match(line)
        if m:
            version = str(m.group(3)) if m.group(2) == "==" else None
            deps.append(Dependency(str(m.group(1)), version, "PyPI", file, i))
    return deps


def _parse_pyproject(text: str, file: str) -> list[Dependency]:
    deps: list[Dependency] = []
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return deps
    project_deps = data.get("project", {}).get("dependencies", [])
    for spec in project_deps:
        m = _REQ_LINE.match(spec if isinstance(spec, str) else "")
        if m:
            version = str(m.group(3)) if m.group(2) == "==" else None
            deps.append(Dependency(str(m.group(1)), version, "PyPI", file, 1))
    return deps


def _parse_package_json(text: str, file: str) -> list[Dependency]:
    deps: list[Dependency] = []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return deps
    for section in ("dependencies", "devDependencies"):
        for name, raw in (data.get(section) or {}).items():
            version = str(raw).lstrip("^~>=< ") if isinstance(raw, str) else None
            pinned = version if isinstance(raw, str) and raw[:1] not in "^~><*" else None
            deps.append(Dependency(str(name), pinned or version, "npm", file, 1))
    return deps


# --- OSV ------------------------------------------------------------------------------------


def query_osv(deps: list[Dependency], config: AnalyzerConfig) -> dict[str, list[str]]:
    """Batch-query OSV.dev for pinned versions. Returns dep_key -> advisory ids."""
    versioned = [d for d in deps if d.version]
    if not versioned or not config.osv_enabled:
        return {}
    payload = {
        "queries": [
            {"package": {"name": d.name, "ecosystem": d.ecosystem}, "version": d.version}
            for d in versioned
        ]
    }
    resp = httpx.post(config.osv_endpoint, json=payload, timeout=config.osv_timeout_seconds)
    resp.raise_for_status()
    results = resp.json().get("results", [])
    out: dict[str, list[str]] = {}
    # strict=True: a short/partial response would mis-map advisories to the wrong package,
    # so we'd rather raise (caller degrades to a safe "OSV unavailable" Info note).
    for dep, result in zip(versioned, results, strict=True):
        vulns = result.get("vulns") or []
        ids = [v.get("id") for v in vulns if v.get("id")]
        if ids:
            out[dep_key(dep)] = ids
    return out


# --- analysis -------------------------------------------------------------------------------


def analyze_supply_chain(
    bundle: Bundle,
    discovery: Discovery,
    config: AnalyzerConfig,
    osv_query: OsvQuery = query_osv,
) -> list[Finding]:
    deps = parse_dependencies(bundle, discovery)
    findings: list[Finding] = []

    findings += _scan_mutable_refs(bundle, discovery)
    findings += _scan_typosquats(deps)

    try:
        advisories = osv_query(deps, config)
    except Exception as exc:  # noqa: BLE001 — any network failure degrades to an Info note
        findings.append(
            make_finding(
                rule_id="supply.osv_unavailable",
                category=Category.SUPPLY_CHAIN,
                severity=Severity.INFO,
                confidence=Confidence.LOW,
                file=str(discovery.primary_path),
                line=None,
                evidence=str(exc)[:120],
                risk="OSV vulnerability check could not run (offline); dependencies were not verified.",
                remediation="Re-run with network access to check dependencies against OSV.dev.",
                source_layer=SourceLayer.SUPPLY_CHAIN,
            )
        )
        advisories = {}

    for dep in deps:
        for adv in advisories.get(dep_key(dep), []):
            findings.append(
                make_finding(
                    rule_id=f"supply.osv_vuln.{dep.name}",
                    category=Category.SUPPLY_CHAIN,
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    file=dep.file,
                    line=dep.line,
                    evidence=f"{dep.name}=={dep.version} → {adv}",
                    risk=f"{dep.name} {dep.version} has a known vulnerability ({adv}).",
                    remediation=f"Upgrade {dep.name} to a patched version per advisory {adv}.",
                    source_layer=SourceLayer.SUPPLY_CHAIN,
                )
            )

    return findings


def _scan_mutable_refs(bundle: Bundle, discovery: Discovery) -> list[Finding]:
    findings: list[Finding] = []
    for comp in discovery.components:
        if comp.type is ComponentType.ASSET:
            continue
        try:
            text = bundle.read_text(comp.path)
        except (OSError, ValueError):
            continue
        for m in _MUTABLE_REF.finditer(text):
            findings.append(
                make_finding(
                    rule_id="supply.mutable_ref",
                    category=Category.SUPPLY_CHAIN,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    file=comp.path,
                    line=text.count("\n", 0, m.start()) + 1,
                    evidence=str(m.group(0)),
                    risk="A mutable ref (branch/HEAD) means the pulled code can change after review.",
                    remediation="Pin dependencies and remote payloads to immutable versions / commit hashes.",
                    source_layer=SourceLayer.SUPPLY_CHAIN,
                )
            )
            break  # one per file
    return findings


def _levenshtein1(a: str, b: str) -> bool:
    if abs(len(a) - len(b)) > 1:
        return False
    if a == b:
        return False
    # check edit distance <= 1
    if len(a) == len(b):
        return sum(x != y for x, y in zip(a, b, strict=False)) == 1
    shorter, longer = (a, b) if len(a) < len(b) else (b, a)
    i = j = 0
    edits = 0
    while i < len(shorter) and j < len(longer):
        if shorter[i] != longer[j]:
            edits += 1
            if edits > 1:
                return False
            j += 1
        else:
            i += 1
            j += 1
    return True


def _scan_typosquats(deps: list[Dependency]) -> list[Finding]:
    findings: list[Finding] = []
    for dep in deps:
        popular = _POPULAR.get(dep.ecosystem, set())
        if dep.name in popular:
            continue
        match = next((p for p in popular if _levenshtein1(dep.name, p)), None)
        if match:
            findings.append(
                make_finding(
                    rule_id=f"supply.typosquat.{dep.name}",
                    category=Category.SUPPLY_CHAIN,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.LOW,
                    file=dep.file,
                    line=dep.line,
                    evidence=f"{dep.name} (looks like {match})",
                    risk=f"`{dep.name}` closely resembles the popular package `{match}` — possible typosquat.",
                    remediation=f"Verify the package name; did you mean `{match}`?",
                    source_layer=SourceLayer.SUPPLY_CHAIN,
                )
            )
    return findings
