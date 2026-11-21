#!/usr/bin/env python3
"""Robustness benchmark against real-world Solidity code.

Downloads well-known, audited packages from npm (OpenZeppelin, Uniswap,
Solmate, Chainlink), then measures parse errors, detector crashes and the
number of findings per severity. Used to keep false positives in check.

    python scripts/benchmark.py            # needs `npm` on PATH
    python scripts/benchmark.py --keep     # keep the downloaded corpus
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path

from chainmail.config import Config
from chainmail.core.parser import parse_source
from chainmail.engine import Scanner

PACKAGES = [
    "@openzeppelin/contracts@5",
    "@openzeppelin/contracts-upgradeable@5",
    "@uniswap/v2-core@1.0.1",
    "@uniswap/v3-core@1.0.1",
    "@uniswap/v2-periphery@1.1.0-beta.0",
    "solmate@6",
    "@chainlink/contracts@1",
]


def fetch(pkg: str, dest: Path) -> Path:
    out = subprocess.run(["npm", "pack", pkg, "--silent"], cwd=dest, capture_output=True, text=True, check=True)
    tgz = dest / out.stdout.strip().splitlines()[-1]
    target = dest / tgz.stem
    target.mkdir(exist_ok=True)
    with tarfile.open(tgz) as tar:
        tar.extractall(target, filter="data")
    return target


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    if shutil.which("npm") is None:
        print("npm is required to download the corpus", file=sys.stderr)
        return 2
    workdir = Path(tempfile.mkdtemp(prefix="chainmail-bench-"))
    print(f"{'package':42} {'files':>5} {'parse err':>9} {'crashes':>7} {'crit':>4} {'high':>4} {'med':>4} {'time':>6}")
    total_files = total_errors = 0
    try:
        for pkg in PACKAGES:
            root = fetch(pkg, workdir)
            files = [p for p in root.rglob("*.sol") if p.is_file() and "/artifacts/" not in p.as_posix()]
            errors = sum(len(parse_source(p.read_text(errors="replace"), str(p)).errors) for p in files)
            started = time.perf_counter()
            result = Scanner(Config()).scan_paths([root])
            c = result.counts
            print(
                f"{pkg:42} {len(files):5} {errors:9} {len(result.detector_errors):7} "
                f"{c['critical']:4} {c['high']:4} {c['medium']:4} {time.perf_counter() - started:5.1f}s"
            )
            total_files += len(files)
            total_errors += errors
    finally:
        if not args.keep:
            shutil.rmtree(workdir, ignore_errors=True)
        else:
            print(f"corpus kept in {workdir}")
    print(f"\n{total_files} files parsed, {total_errors} parse errors")
    return 0


if __name__ == "__main__":
    sys.exit(main())
