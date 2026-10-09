#!/usr/bin/env python3
"""Compile, recover, recompile, and behavior-check the hello sample."""

from __future__ import annotations

import os
import pathlib
import subprocess
import sys
import tempfile


def run(command: list[str], cwd: pathlib.Path) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        raise RuntimeError(
            "command failed with exit code "
            f"{result.returncode}: {' '.join(command)}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: roundtrip_test.py <caraxes> <hello.c>", file=sys.stderr)
        return 2

    caraxes = pathlib.Path(sys.argv[1]).resolve()
    source = pathlib.Path(sys.argv[2]).resolve()
    compiler = os.environ.get("CC", "gcc")

    with tempfile.TemporaryDirectory(prefix="caraxes-roundtrip-") as directory:
        work = pathlib.Path(directory)
        original = work / "hello"
        recovered_source = work / "recovered.c"
        recovered = work / "recovered"

        run([compiler, "-std=c11", "-O0", "-g", str(source), "-o", str(original)], work)
        original_run = subprocess.run(
            [str(original)],
            cwd=work,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        run([str(caraxes), "decompile", str(original), "--output", str(recovered_source)], work)
        run(
            [
                compiler,
                "-std=c11",
                "-Wall",
                "-Wextra",
                "-Werror",
                str(recovered_source),
                "-o",
                str(recovered),
            ],
            work,
        )
        recovered_run = subprocess.run(
            [str(recovered)],
            cwd=work,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        if original_run.returncode != recovered_run.returncode:
            raise RuntimeError(
                "round-trip exit status mismatch: "
                f"original={original_run.returncode}, recovered={recovered_run.returncode}\n"
                f"recovered stderr:\n{recovered_run.stderr}"
            )
        if original_run.stdout != recovered_run.stdout:
            raise RuntimeError(
                "round-trip stdout mismatch\n"
                f"original: {original_run.stdout!r}\n"
                f"recovered: {recovered_run.stdout!r}\n"
                f"recovered stderr:\n{recovered_run.stderr}"
            )
        if not original_run.stderr == recovered_run.stderr == "":
            raise RuntimeError(
                "round-trip stderr mismatch\n"
                f"original: {original_run.stderr!r}\n"
                f"recovered: {recovered_run.stderr!r}"
            )

        print("Caraxes round-trip passed: compile -> recover -> compile -> compare")
        print(f"stdout: {original_run.stdout.rstrip()}")
        return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError) as error:
        print(f"round-trip test failed: {error}", file=sys.stderr)
        raise SystemExit(1)
