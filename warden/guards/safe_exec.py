"""
warden/guards/safe_exec.py

Argument parameterization — the defense against shell-injection / RCE when a
tool ultimately hands arguments to the operating system.

Two rules, in priority order:

  1. NEVER build a shell string. Always execute with an explicit argument
     list and shell=False, so the OS shell never interprets metacharacters
     like ; | & $ ` and command chaining is impossible by construction.

  2. As defense in depth, screen individual arguments for shell
     metacharacters anyway. Even though rule 1 makes them inert, a tool that
     *needs* a value containing one of these is rare, and flagging them lets
     policy decide (deny vs. allow) rather than passing them blindly.

v1 does NOT enable any shell-style tool (run_command is tier: deny in the
default policy). This module exists so that if/when such a tool is added, the
safe path is the only path available.
"""

import shlex
import subprocess
from typing import Sequence


# Characters that enable command chaining / substitution in a POSIX shell.
_SHELL_METACHARACTERS = set(";|&$`\n\r<>(){}!*?[]~")


class UnsafeArgumentError(Exception):
    """Raised when an argument contains shell metacharacters and strict mode is on."""


def screen_arguments(args: Sequence[str], strict: bool = True) -> list[str]:
    """Check each argument for shell metacharacters.

    In strict mode, raises on the first offending argument. In non-strict
    mode, returns the args unchanged (the caller has decided the risk is
    acceptable because execution is shell=False anyway).
    """
    for arg in args:
        if any(ch in _SHELL_METACHARACTERS for ch in str(arg)):
            if strict:
                raise UnsafeArgumentError(
                    f"argument contains shell metacharacters: {arg!r}"
                )
    return list(args)


def run_parameterized(argv: Sequence[str], timeout: int = 30, cwd: str | None = None):
    """Execute a command the ONLY safe way: an argument vector, shell=False.

    Never accept a single string here. If a caller has a string, that is a
    bug — parse intent upstream into an explicit argv. shlex.split is offered
    as a helper for that upstream parsing, but this function refuses a bare
    string to make the unsafe path impossible.
    """
    if isinstance(argv, str):
        raise TypeError(
            "run_parameterized requires an argument list, not a string. "
            "Parse intent into an explicit argv upstream (see shlex.split)."
        )
    return subprocess.run(
        list(argv),
        shell=False,          # the one non-negotiable line in this file
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=cwd,
    )


def parse_to_argv(command_string: str) -> list[str]:
    """Helper for upstream code that must turn a string into a safe argv.

    Uses shlex so quoting is respected and the result is a clean token list
    to feed run_parameterized. This does not itself execute anything.
    """
    return shlex.split(command_string)
