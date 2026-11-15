"""Tests for cyber_sentinel.tools and scripts/."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from click.testing import CliRunner

from cyber_sentinel.cli.main import cli
from cyber_sentinel.tools.bench_matrix import BenchMatrixRunner
from cyber_sentinel.tools.doctor import run_doctor

ROOT = Path(__file__).resolve().parent.parent


def test_doctor_healthy() -> None:
    report = run_doctor()
    assert report.healthy is True
    assert report.sg5_injection_probe_ok is True
    assert report.sg6_secret_probe_ok is True
    assert report.sg4_ssrf_probe_ok is True
    assert report.pod9_envelope_probe_ok is True


def test_bench_matrix_runner() -> None:
    runner = BenchMatrixRunner(batch_sizes=[10], reps=1)
    data = runner.run_matrix()
    assert len(data["matrix_results"]) == 3
    md = BenchMatrixRunner.format_markdown_table(data)
    assert "| sg5_prompt | 10 |" in md
    assert "| sg6_secret | 10 |" in md
    assert "| sg4_tool | 10 |" in md


def test_cli_doctor_and_matrix() -> None:
    runner = CliRunner()
    res_doc = runner.invoke(cli, ["doctor", "--json"])
    assert res_doc.exit_code == 0
    assert json.loads(res_doc.output)["healthy"] is True

    res_mat = runner.invoke(cli, ["matrix", "--batches", "10", "--reps", "1", "--json"])
    assert res_mat.exit_code == 0
    assert len(json.loads(res_mat.output)["matrix_results"]) == 3


def test_scripts_run_cleanly() -> None:
    bench = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "benchmark_sentinel_latency.py"), "--batches", "10", "--reps", "1", "--json"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert len(json.loads(bench.stdout)["matrix_results"]) == 3

    gate = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "gate_pod9_defense_runner.py"), "--json"],
        capture_output=True,
        text=True,
        check=True,
    )
    gate_data = json.loads(gate.stdout)
    assert gate_data["approved"] is True
    assert all(c["passed"] for c in gate_data["checks"])
