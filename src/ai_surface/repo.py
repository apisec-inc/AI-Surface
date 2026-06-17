"""Clone a remote git repo to a temp dir for scanning, then discard it.

Used by `ai-surface scan --repo <url>` and the local UI's /api/scan endpoint.

Privacy: the clone runs on the machine invoking ai-surface (your laptop or your
CI runner), the same place a local scan runs. Source is read locally and the
temp clone is always removed afterwards. A private-repo token is used only to
authenticate the clone subprocess; it is never stored, logged, or written to
any report.
"""
from __future__ import annotations

import ipaddress
import re
import shutil
import subprocess
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit

# Only https git URLs. No ssh, no file://, no shell metacharacters. We pass
# args as a list (never shell=True), so this is defense-in-depth, not the only
# guard. Keep the charset tight.
_URL_RE = re.compile(r"^https://[A-Za-z0-9._~:/?#@!$&'()*+,;=%-]+$")


class RepoError(RuntimeError):
    """A clone could not be performed. Message is safe to show the user."""


def _origin_url(git_config_text: str) -> str:
    """Return the ``origin`` remote URL from a .git/config body, or ''."""
    in_origin = False
    for raw in git_config_text.splitlines():
        line = raw.strip()
        if line.startswith("["):
            in_origin = line.replace(" ", "").lower() == '[remote"origin"]'
            continue
        if in_origin and line.lower().startswith("url"):
            parts = line.split("=", 1)
            if len(parts) == 2:
                return parts[1].strip()
    return ""


def _normalize_repo(url: str) -> str:
    """Normalize a git remote URL to ``owner/repo`` (known forges) or ``host/path``.

    Strips a trailing ``.git`` and any embedded credentials (``user:token@``) so
    a tokenized remote can never leak into a report.
    """
    u = url.strip()
    if u.endswith(".git"):
        u = u[:-4]
    host = path = ""
    ssh = re.match(r"^[\w.-]+@([^:]+):(.+)$", u)  # git@github.com:owner/repo
    if ssh:
        host, path = ssh.group(1), ssh.group(2)
    else:
        https = re.match(r"^[a-zA-Z]+://([^/]+)/(.+)$", u)
        if https:
            host, path = https.group(1), https.group(2)
        else:
            return ""  # unrecognized form; don't guess
    if "@" in host:  # strip userinfo / credentials
        host = host.rsplit("@", 1)[-1]
    host = host.split(":", 1)[0]  # drop any :port
    if host.lower() in ("github.com", "gitlab.com", "bitbucket.org"):
        return path
    return f"{host}/{path}"


def detect_repository(scan_root: str) -> str:
    """Best-effort origin remote of the scanned repo as ``owner/repo``.

    Reads ``<scan_root>/.git/config`` directly (no subprocess, no network).
    Returns '' when the path is not a git repo or has no origin remote.
    """
    cfg = Path(scan_root) / ".git" / "config"
    if not cfg.is_file():
        return ""
    try:
        text = cfg.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    url = _origin_url(text)
    return _normalize_repo(url) if url else ""


def _validate_url(url: str) -> None:
    if not url or not _URL_RE.match(url):
        raise RepoError(
            "only https git URLs are supported (e.g. https://github.com/org/repo)"
        )
    if ".." in url:
        raise RepoError("invalid repository URL")
    parts = urlsplit(url)
    # Credentials belong in the token argument, never embedded in the URL.
    if parts.username or parts.password or "@" in parts.netloc:
        raise RepoError("credentials must not be embedded in the repository URL")
    host = (parts.hostname or "").lower()
    if not host:
        raise RepoError("invalid repository URL")
    # Refuse internal / loopback targets so --repo (and the UI's /api/scan)
    # cannot be pointed at internal git servers or the cloud metadata endpoint
    # (SSRF). git clone speaks the smart-HTTP handshake, not arbitrary HTTP, so
    # this is defense in depth, but it closes internal-host probing.
    if host == "localhost" or host.endswith((".localhost", ".internal", ".local")):
        raise RepoError("refusing to clone from a private/internal host")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None and (
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_reserved or ip.is_unspecified or ip.is_multicast
    ):
        raise RepoError("refusing to clone from a private/internal address")


def _authed_url(url: str, token: str | None) -> str:
    """Inject a token for a private https clone. Returns url unchanged if no token."""
    if not token:
        return url
    return url.replace("https://", f"https://x-access-token:{token}@", 1)


def clone_repo_to_tmp(
    url: str,
    token: str | None = None,
    timeout: int = 180,
) -> tuple[Path, Callable[[], None]]:
    """Shallow-clone `url` into a temp dir. Returns (path, cleanup).

    The caller MUST call cleanup() when done (use clone_repo() for an
    auto-cleaning context manager). Raises RepoError on any failure.
    """
    _validate_url(url)
    tmp = Path(tempfile.mkdtemp(prefix="ai-surface-clone-"))

    def cleanup() -> None:
        shutil.rmtree(tmp, ignore_errors=True)

    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", "--quiet", _authed_url(url, token), str(tmp)],
            check=True,
            capture_output=True,
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        cleanup()
        raise RepoError("git is not installed; --repo requires git on PATH") from exc
    except subprocess.TimeoutExpired as exc:
        cleanup()
        raise RepoError(f"clone timed out after {timeout}s") from exc
    except subprocess.CalledProcessError as exc:
        cleanup()
        stderr = (exc.stderr or b"").decode("utf-8", "replace")
        if token:
            stderr = stderr.replace(token, "***")  # never echo the token
        raise RepoError(f"git clone failed: {stderr.strip()[:300]}") from exc

    return tmp, cleanup


@contextmanager
def clone_repo(url: str, token: str | None = None) -> Iterator[Path]:
    """Context manager: clone `url`, yield the local path, always clean up."""
    path, cleanup = clone_repo_to_tmp(url, token)
    try:
        yield path
    finally:
        cleanup()
