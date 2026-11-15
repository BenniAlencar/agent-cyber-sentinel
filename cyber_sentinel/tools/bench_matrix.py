"""Matrix Benchmark Suite for Agent Cyber Sentinel.

Sweeps payload batch sizes across SG-5 (Prompt Injection), SG-6 (Secret Redaction),
and SG-4 (Tool Sanitization) to measure per-inspection latency and throughput.
"""

from __future__ import annotations

import argparse
import json
import statistics
import time
from typing import Any

from cyber_sentinel.shield import CyberSentinel


class BenchMatrixRunner:
    """Executes a multi-gate, multi-batch latency & throughput benchmark matrix."""

    def __init__(
        self,
        batch_sizes: list[int] | None = None,
        gates: list[str] | None = None,
        reps: int = 2,
    ) -> None:
        self.batch_sizes = batch_sizes or [50, 200, 500]
        self.gates = gates or ["sg5_prompt", "sg6_secret", "sg4_tool"]
        self.reps = reps

    def _run_once(self, gate: str, n: int) -> float:
        sentinel = CyberSentinel(strict=False, auto_redact_secrets=True)
        t0 = time.perf_counter()
        if gate == "sg5_prompt":
            for i in range(n):
                sentinel.inspect_prompt(f"Summarize quarterly metrics for region_{i} safely.")
        elif gate == "sg6_secret":
            for i in range(n):
                sentinel.inspect_output(f"Log {i}: key=sk-proj-1234567890abcdef1234567890abcdef1234567890abcdef")
        elif gate == "sg4_tool":
            for i in range(n):
                sentinel.inspect_tool_call("http_get", {"url": f"https://api.example.com/v1/items/{i}"})
        return max(1e-6, time.perf_counter() - t0)

    def run_matrix(self) -> dict[str, Any]:
        """Run the benchmark sweep across all gates and batch sizes."""
        rows: list[dict[str, Any]] = []
        for gate in self.gates:
            for n in self.batch_sizes:
                samples = [self._run_once(gate, n) for _ in range(self.reps)]
                mean_s = statistics.mean(samples)
                rows.append(
                    {
                        "gate": gate,
                        "batch_size": n,
                        "total_ms": round(mean_s * 1000.0, 2),
                        "mean_item_ms": round((mean_s * 1000.0) / n, 4),
                        "ops_per_sec": round(n / mean_s, 1),
                    }
                )
        return {
            "gates": self.gates,
            "batch_sizes": self.batch_sizes,
            "reps": self.reps,
            "matrix_results": rows,
            "timestamp": int(time.time()),
        }

    @staticmethod
    def format_markdown_table(data: dict[str, Any]) -> str:
        """Render a Markdown summary table from benchmark matrix results."""
        lines = [
            "# Agent Cyber Sentinel Benchmark Matrix",
            "",
            "| Gate | Batch Size | Total Time (ms) | Mean Item (ms) | Throughput (ops/s) |",
            "|---|---:|---:|---:|---:|",
        ]
        for row in data.get("matrix_results", []):
            lines.append(
                f"| {row['gate']} | {row['batch_size']} | {row['total_ms']} | "
                f"{row['mean_item_ms']} | {row['ops_per_sec']} |"
            )
        return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run Agent Cyber Sentinel benchmark matrix.")
    parser.add_argument("--batches", type=int, nargs="+", default=[50, 200, 500], help="Batch sizes to sweep.")
    parser.add_argument("--reps", type=int, default=2, help="Repetitions per cell.")
    parser.add_argument("--json", action="store_true", help="Emit JSON output.")
    args = parser.parse_args(argv)

    runner = BenchMatrixRunner(batch_sizes=args.batches, reps=args.reps)
    data = runner.run_matrix()
    if args.json:
        print(json.dumps(data, indent=2))
    else:
        print(runner.format_markdown_table(data))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
