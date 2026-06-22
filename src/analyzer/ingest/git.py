"""Git ingest — shallow clone with submodules + hooks disabled (§3, §6.4).

We never run anything from the cloned repo. After cloning we read commit/author/
branch metadata (as untrusted data), strip the ``.git`` directory so its internals
aren't scanned as artifact content, and enforce the size/file-count caps.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from analyzer.bundle import Bundle
from analyzer.config import AnalyzerConfig
from analyzer.ingest.archive import IngestError


def _git_env() -> dict[str, str]:
    env = dict(os.environ)
    # never block on a credential / host-key prompt; keep the clone non-interactive
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_ASKPASS"] = "true"
    env["GIT_SSH_COMMAND"] = "ssh -oBatchMode=yes -oStrictHostKeyChecking=accept-new"
    return env


def _capture_metadata(dest: Path, env: dict[str, str]) -> dict[str, str]:
    def _git(*args: str) -> str:
        try:
            out = subprocess.run(
                ["git", *args], cwd=dest, env=env, capture_output=True, text=True, timeout=15
            )
            return out.stdout.strip()
        except (subprocess.SubprocessError, OSError):
            return ""

    return {
        "commit_message": _git("log", "-1", "--format=%s"),
        "author": _git("log", "-1", "--format=%an"),
        "author_email": _git("log", "-1", "--format=%ae"),
        "branch": _git("rev-parse", "--abbrev-ref", "HEAD"),
    }


def _enforce_caps(root: Path, config: AnalyzerConfig) -> None:
    count = 0
    total = 0
    for path in root.rglob("*"):
        if path.is_symlink() or not path.is_file():
            continue
        count += 1
        if count > config.max_file_count:
            raise IngestError("cloned repo exceeds max file count")
        total += path.stat().st_size
        if total > config.max_total_bytes:
            raise IngestError("cloned repo exceeds total size cap")


def _is_remote_url(url: str) -> bool:
    """True for an https/http/git/ssh URL or scp-like ``user@host:path`` — i.e. not a
    local filesystem path or ``file://`` URL."""
    if "://" in url:
        return url.split("://", 1)[0].lower() in ("https", "http", "git", "ssh")
    # scp-like syntax: user@host:path (colon before any slash)
    colon, slash = url.find(":"), url.find("/")
    return "@" in url and colon != -1 and (slash == -1 or colon < slash)


def ingest_git(url: str, config: AnalyzerConfig, *, allow_local: bool = False) -> Bundle:
    """Shallow-clone ``url`` into a sandbox dir and return a Bundle.

    ``allow_local`` permits filesystem-path / ``file://`` clones — keep it False for
    untrusted submissions (it widens host-filesystem exposure); tests opt in.
    """
    if url.startswith("-"):
        raise IngestError(f"refusing git url that looks like an option: {url!r}")
    if not allow_local and not _is_remote_url(url):
        raise IngestError("only remote https/http/git/ssh URLs are accepted")

    root = Path(tempfile.mkdtemp(prefix="ssa-git-"))
    dest = root  # clone directly into the sandbox root
    env = _git_env()

    cmd = [
        "git",
        "-c",
        "core.hooksPath=/dev/null",  # never honor any hooks
        "-c",
        f"protocol.file.allow={'always' if allow_local else 'never'}",
        "clone",
        "--depth=1",
        "--no-tags",
        "--single-branch",
        "--",  # end of options: a hostile url can never be parsed as a git flag
        url,
        str(dest),
    ]
    try:
        result = subprocess.run(
            cmd, env=env, capture_output=True, text=True, timeout=config.git_timeout_seconds
        )
    except (subprocess.SubprocessError, OSError) as exc:
        shutil.rmtree(root, ignore_errors=True)
        raise IngestError(f"git clone failed: {exc}") from exc

    if result.returncode != 0:
        shutil.rmtree(root, ignore_errors=True)
        raise IngestError(f"git clone failed: {result.stderr.strip()[:500]}")

    bundle = Bundle(root=root, source_mode="git")
    try:
        bundle.git_metadata = _capture_metadata(dest, env)
        shutil.rmtree(dest / ".git", ignore_errors=True)  # don't scan git internals
        _enforce_caps(root, config)
    except Exception:
        bundle.cleanup()
        raise

    return bundle
