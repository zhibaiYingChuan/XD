"""道体·玄盾命令行管理工具。

用法：
    python -m daoti_xuandun.manage init --domain mydata.txt
    python -m daoti_xuandun.manage export --output profile.json
    python -m daoti_xuandun.manage import --input profile.json
    python -m daoti_xuandun.manage test --level STANDARD
    python -m daoti_xuandun.manage recommend --domain mydata.txt

活性防护哲学：管理工具简化运维，让安全管理员无需写代码
即可完成预热、导入/导出、测试等操作。
"""

import argparse
import json

from daoti_xuandun.config import DefenseLevel, XuanDunConfig
from daoti_xuandun.xuandun import XuanDun


def cmd_init(args):
    """初始化域档案：从领域样本文件预热。"""
    config = XuanDunConfig.for_level(DefenseLevel[args.level])
    xuandun = XuanDun(config)

    if args.domain:
        with open(args.domain, "r", encoding="utf-8") as f:
            texts = [line.strip() for line in f if line.strip()]
        for i, text in enumerate(texts):
            xuandun.protect(text, session_id=f"init_{i}")
        print(f"[INFO] Warmed up with {len(texts)} domain samples from {args.domain}")
    else:
        print("[INFO] Auto-warmup completed with built-in safe samples.")

    if args.output:
        profile = xuandun.export_domain_profile()
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(profile, f, ensure_ascii=False, indent=2)
        print(f"[INFO] Domain profile exported to {args.output}")

    rec = config.recommendation()
    print(f"[INFO] Defense level: {rec['defense_level']}")
    print(f"[INFO] Safety score: {rec['safety_score']}/100")
    for s in rec["suggestions"]:
        print(f"[HINT] {s}")


def cmd_export(args):
    """导出域档案到JSON文件。"""
    config = XuanDunConfig.for_level(DefenseLevel[args.level])
    xuandun = XuanDun(config)

    if args.domain:
        with open(args.domain, "r", encoding="utf-8") as f:
            texts = [line.strip() for line in f if line.strip()]
        for i, text in enumerate(texts):
            xuandun.protect(text, session_id=f"init_{i}")

    sanitize = not args.raw
    profile = xuandun.export_domain_profile(sanitize=sanitize)
    output = args.output or "domain_profile.json"
    with open(output, "w", encoding="utf-8") as f:
        json.dump(profile, f, ensure_ascii=False, indent=2)
    if sanitize:
        print(f"[INFO] Domain profile exported (sanitized) to {output}")
        print("[HINT] Use --raw flag to export importable profile (trusted environments only)")
    else:
        print(f"[INFO] Domain profile exported (raw) to {output}")
        print("[WARN] Raw profile contains sensitive data, handle with care")


def cmd_import(args):
    """从JSON文件导入域档案。"""
    config = XuanDunConfig.for_level(DefenseLevel[args.level])
    xuandun = XuanDun(config)

    with open(args.input, "r", encoding="utf-8") as f:
        profile = json.load(f)
    xuandun.import_domain_profile(profile)
    print(f"[INFO] Domain profile imported from {args.input}")


def cmd_test(args):
    """运行基准测试。"""
    from daoti_xuandun.benchmark.runner import BenchmarkRunner

    runner = BenchmarkRunner(DefenseLevel[args.level])
    report = runner.run_all()
    s = report.summary
    print(f"\n[RESULT] Attack rejection rate: {s.get('attack_reject_rate_pct', 0):.1f}%")
    print(f"[RESULT] Out-domain acceptance rate: {s.get('out_domain_accept_rate_pct', 0):.1f}%")
    print(f"[RESULT] In-domain pass rate: {s.get('in_domain_pass_rate_pct', 0):.1f}%")


def cmd_recommend(args):
    """根据领域样本推荐配置。"""
    if args.domain:
        with open(args.domain, "r", encoding="utf-8") as f:
            texts = [line.strip() for line in f if line.strip()]
    else:
        texts = []

    config = XuanDunConfig.tune_for_domain(texts, DefenseLevel[args.level])
    rec = config.recommendation()

    print(f"Recommended defense level: {rec['defense_level']}")
    print(f"Safety score: {rec['safety_score']}/100")
    print(f"Estimated performance overhead: {rec['performance_overhead_pct']}%")
    print("Suggestions:")
    for s in rec["suggestions"]:
        print(f"  - {s}")


def main():
    parser = argparse.ArgumentParser(
        prog="daoti_xuandun.manage",
        description="道体·玄盾命令行管理工具",
        epilog=(
            "常用命令速查:\n"
            "  python -m daoti_xuandun.manage init --domain mydata.txt --output profile.json\n"
            "  python -m daoti_xuandun.manage export --output profile.json\n"
            "  python -m daoti_xuandun.manage import --input profile.json\n"
            "  python -m daoti_xuandun.manage test --level STANDARD\n"
            "  python -m daoti_xuandun.manage recommend --domain mydata.txt\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    p_init = subparsers.add_parser("init", help="Initialize domain profile")
    p_init.add_argument("--domain", help="Domain sample file (one per line)")
    p_init.add_argument("--level", default="STANDARD", choices=["BASIC", "STANDARD", "STRICT", "PARANOID"])
    p_init.add_argument("--output", help="Output profile JSON path")

    p_export = subparsers.add_parser("export", help="Export domain profile")
    p_export.add_argument("--domain", help="Domain sample file for warmup")
    p_export.add_argument("--level", default="STANDARD", choices=["BASIC", "STANDARD", "STRICT", "PARANOID"])
    p_export.add_argument("--output", help="Output JSON path")
    p_export.add_argument("--raw", action="store_true", help="Export raw (importable) profile, NOT sanitized")

    p_import = subparsers.add_parser("import", help="Import domain profile")
    p_import.add_argument("--input", required=True, help="Input profile JSON path")
    p_import.add_argument("--level", default="STANDARD", choices=["BASIC", "STANDARD", "STRICT", "PARANOID"])

    p_test = subparsers.add_parser("test", help="Run benchmark test")
    p_test.add_argument("--level", default="STANDARD", choices=["BASIC", "STANDARD", "STRICT", "PARANOID"])

    p_rec = subparsers.add_parser("recommend", help="Recommend configuration")
    p_rec.add_argument("--domain", help="Domain sample file for tuning")
    p_rec.add_argument("--level", default="STANDARD", choices=["BASIC", "STANDARD", "STRICT", "PARANOID"])

    args = parser.parse_args()

    if args.command == "init":
        cmd_init(args)
    elif args.command == "export":
        cmd_export(args)
    elif args.command == "import":
        cmd_import(args)
    elif args.command == "test":
        cmd_test(args)
    elif args.command == "recommend":
        cmd_recommend(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
