# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白
# 本文件受道体研究许可证 v1.0 约束，禁止逆向工程和再分发
# 详见 LICENSE 文件

"""道体·玄盾 行业基准测试模块（三阶段评估）。

参照 OWASP AITG / NIST Dioptra / garak 等框架，
对内嵌攻击数据集进行三阶段系统性安全评估。

Usage:
    from daoti_xuandun.benchmark import BenchmarkRunner
    from daoti_xuandun.config import DefenseLevel

    runner = BenchmarkRunner(DefenseLevel.STANDARD)
    runner.seed_domains(["论语", "道德经", "黄帝内经"])
    report = runner.run_all()
    runner.save_reports("benchmark_results")
"""

from daoti_xuandun.benchmark.runner import BenchmarkRunner, run_full_benchmark
from daoti_xuandun.benchmark.report import BenchmarkReport
from daoti_xuandun.benchmark.datasets import ProbeDataset, build_all_datasets
from daoti_xuandun.benchmark.probes import (
    ThreeStageReport,
    ProbeResult,
    run_probe_three_stage,
    run_avalanche_probe,
    run_session_isolation_probe,
    run_data_contamination_probe,
    run_trust_escalation_probe,
    run_repeated_benign_probe,
)

__all__ = [
    "BenchmarkRunner",
    "BenchmarkReport",
    "ProbeDataset",
    "ThreeStageReport",
    "ProbeResult",
    "run_full_benchmark",
    "run_probe_three_stage",
    "run_avalanche_probe",
    "run_session_isolation_probe",
    "run_data_contamination_probe",
    "run_trust_escalation_probe",
    "run_repeated_benign_probe",
    "build_all_datasets",
]