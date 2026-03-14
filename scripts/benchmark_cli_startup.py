"""Simple benchmark helper for lightweight CLI startup paths.

Run from the pufferblow repo root, ideally inside WSL:

    poetry run python scripts/benchmark_cli_startup.py
"""

from __future__ import annotations

import statistics
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
COMMANDS: dict[str, list[str]] = {
    "help": [sys.executable, "-m", "pufferblow.cli.cli", "--help"],
    "version": [sys.executable, "-m", "pufferblow.cli.cli", "version"],
    "serve-help": [sys.executable, "-m", "pufferblow.cli.cli", "serve", "--help"],
    "storage-help": [sys.executable, "-m", "pufferblow.cli.cli", "storage", "--help"],
}
RUNS = 5


def run_once(command: list[str]) -> float:
    start = time.perf_counter()
    completed = subprocess.run(
        command,
        cwd=REPO_ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=True,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"Command failed: {' '.join(command)}")
    return time.perf_counter() - start


def main() -> None:
    print("Pufferblow CLI startup benchmark")
    print(f"runs_per_command={RUNS}")
    for name, command in COMMANDS.items():
        samples = [run_once(command) for _ in range(RUNS)]
        average = statistics.mean(samples)
        minimum = min(samples)
        maximum = max(samples)
        print(
            f"{name:12} avg={average * 1000:.1f}ms "
            f"min={minimum * 1000:.1f}ms max={maximum * 1000:.1f}ms"
        )


if __name__ == "__main__":
    main()
