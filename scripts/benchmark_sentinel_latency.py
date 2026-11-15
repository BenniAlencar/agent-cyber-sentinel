#!/usr/bin/env python3
"""POD-9 Runtime Defense Latency & Throughput Benchmark.

Measures per-payload inspection latency across SG-5 (Prompt Injection),
SG-6 (Secret Leak Redaction), and SG-4 (SSRF & Tool Call Sanitization).

Usage:
    python scripts/benchmark_sentinel_latency.py
    python scripts/benchmark_sentinel_latency.py --batches 50 200 500 --reps 2
    python scripts/benchmark_sentinel_latency.py --json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from cyber_sentinel.tools.bench_matrix import BenchMatrixRunner


def run_benchmark(batches: list[int] | None = None, reps: int = 2) -> dict[str, Any]:
    """Execute the Cyber Sentinel latency matrix benchmark."""
    runner = BenchMatrixRunner(batch_sizes=batches or [50, 200, 500], reps=reps)
    return runner.run_matrix()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Benchmark Agent Cyber Sentinel latency.")
    parser.add_argument("--batches", type=int, nargs="+", default=[50, 200, 500], help="Batch sizes to sweep.")
    parser.add_argument("--reps", type=int, default=2, help="Repetitions per cell.")
    parser.add_argument("--json", action="store_true", help="Emit JSON report.")
    args = parser.parse_args(argv)

    data = run_benchmark(batches=args.batches, reps=args.reps)
    if args.json:
        print(json.dumps(data, indent=2))
    else:
        print(BenchMatrixRunner.format_markdown_table(data))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
