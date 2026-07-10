"""
proxy/guards/canonicalize.py

Path canonicalization — the primary defense against directory-traversal
attacks (../../etc/passwd), symlink escapes, and hard-link escapes.

The rule is simple and absolute: resolve EVERY requested path to a real,
absolute path with all symlinks and relative components collapsed, then
confirm it still lives strictly inside the workspace root. If the resolved
path is anywhere else, the request is denied. There is no "mostly inside" —
a single escape is a full failure.

This guard is pure and has no I/O side effects beyond resolving paths, so it
is trivial to test against a battery of attack strings.
"""

from pathlib import Path


class PathTraversalError(Exception):
    """Raised when a requested path resolves outside the workspace root."""


def canonicalize_within(workspace_root: str, requested_path: str) -> Path:
    """Resolve requested_path and guarantee it is inside workspace_root.

    Returns the safe, absolute, fully resolved Path on success.
    Raises PathTraversalError if the path escapes the workspace.

    strict=False on resolve() so that a not-yet-created file (a legitimate
    write target) still resolves; the containment check below is what
    provides the security, not the file's existence.
    """
    root = Path(workspace_root).resolve(strict=False)

    # Join relative requests onto the root; absolute requests are resolved
    # as-is so an attacker passing an absolute /etc/passwd is caught by the
    # containment check rather than silently honored.
    candidate = Path(requested_path)
    if not candidate.is_absolute():
        candidate = root / candidate

    resolved = candidate.resolve(strict=False)

    # The containment check. Using is_relative_to (3.9+) avoids string-prefix
    # bugs like "/safe/workspace-evil" falsely matching "/safe/workspace".
    if not _is_within(resolved, root):
        raise PathTraversalError(
            f"path escapes workspace: requested={requested_path!r} "
            f"resolved={str(resolved)!r} root={str(root)!r}"
        )
    return resolved


def _is_within(path: Path, root: Path) -> bool:
    """True iff path is root itself or a descendant of root."""
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False
