#!/usr/bin/env python3
"""Python entrypoint for the standard DDoS defense demo.

The standard demo implementation already lives in scripts/run_demo.sh.
This wrapper keeps that tested flow intact while providing a Python script that
can be used by graders or automation.
"""

from __future__ import annotations

import os
import shlex
import subprocess
import sys
from pathlib import Path


def _path_for_bash(path: Path, bash_bin: str) -> str:
    """Return a path that the selected bash can use."""
    if os.name != "nt":
        return str(path)

    env = os.environ.copy()
    env["CS3611_WRAPPER_PATH"] = str(path)
    converters = (
        'command -v wslpath >/dev/null 2>&1 && wslpath -a "$CS3611_WRAPPER_PATH"',
        'command -v cygpath >/dev/null 2>&1 && cygpath -u "$CS3611_WRAPPER_PATH"',
    )
    for converter in converters:
        completed = subprocess.run(
            [bash_bin, "-lc", converter],
            env=env,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            text=True,
            check=False,
        )
        converted = completed.stdout.strip()
        if completed.returncode == 0 and converted:
            return converted

    return str(path)


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    root_dir = Path(__file__).resolve().parents[1]
    shell_script = root_dir / "scripts" / "run_demo.sh"

    if not shell_script.is_file():
        print(f"[demo][error] missing shell script: {shell_script}", file=sys.stderr)
        return 1

    bash_bin = os.environ.get("BASH", "bash")

    try:
        bash_root = _path_for_bash(root_dir, bash_bin)
        command_text = f"cd {shlex.quote(bash_root)} && exec bash scripts/run_demo.sh"
        if args:
            command_text += " " + " ".join(shlex.quote(arg) for arg in args)
        completed = subprocess.run([bash_bin, "-lc", command_text], cwd=root_dir, check=False)
    except FileNotFoundError:
        print(
            f"[demo][error] bash executable not found: {bash_bin}. "
            "Run in Linux/WSL/Git Bash, or set BASH=/path/to/bash.",
            file=sys.stderr,
        )
        return 127

    return int(completed.returncode)


if __name__ == "__main__":
    raise SystemExit(main())
