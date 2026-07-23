# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白
# 本文件受道体研究许可证 v1.0 约束，禁止逆向工程和再分发
# 详见 LICENSE 文件

"""配置备份/回滚机制 — 每次变更前自动备份，支持一键回滚。

用法：
  python -m daoti_xuandun.tools.config_snapshot --backup
  python -m daoti_xuandun.tools.config_snapshot --list
  python -m daoti_xuandun.tools.config_snapshot --restore <id>
  python -m daoti_xuandun.tools.config_snapshot --restore latest

备份内容：
  - config 参数（所有 XuanDunConfig 字段）
  - 学习状态统计（模式、样本数、原型数，不含原始原型数据）
  - 时间戳和变更原因

保留最近 5 个快照，超出自动清理最旧的。
"""

import argparse
import json
import sys
import time
from dataclasses import asdict
from pathlib import Path
from typing import Optional


def _snapshot_dir() -> Path:
    """获取快照存储目录。"""
    d = Path.home() / ".xuandun" / "config_snapshots"
    d.mkdir(parents=True, exist_ok=True)
    return d


def create_snapshot(shield, reason: str = "manual") -> dict:
    """创建配置快照。

    Args:
        shield: XuanDun 实例
        reason: 变更原因

    Returns:
        快照信息字典
    """
    ts = time.strftime("%Y%m%d_%H%M%S")
    snapshot_id = f"snap_{ts}"

    config = shield.config
    config_data = asdict(config)

    learning_status = shield.get_learning_status()

    snapshot = {
        "id": snapshot_id,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "reason": reason,
        "config": config_data,
        "learning_status": learning_status,
    }

    path = _snapshot_dir() / f"{snapshot_id}.json"
    path.write_text(json.dumps(snapshot, ensure_ascii=False, indent=2), encoding="utf-8")

    # 清理旧快照，保留最近 5 个
    _cleanup_old_snapshots(keep=5)

    return {
        "ok": True,
        "id": snapshot_id,
        "path": str(path),
        "reason": reason,
        "timestamp": snapshot["timestamp"],
    }


def list_snapshots() -> list:
    """列出所有快照。"""
    snapshots = []
    for p in sorted(_snapshot_dir().glob("snap_*.json"), reverse=True):
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            snapshots.append({
                "id": data["id"],
                "timestamp": data["timestamp"],
                "reason": data.get("reason", ""),
                "mode": data.get("learning_status", {}).get("mode", ""),
                "sample_count": data.get("learning_status", {}).get("sample_count", 0),
            })
        except Exception:
            continue
    return snapshots


def restore_snapshot(snapshot_id: str) -> dict:
    """回滚到指定快照。

    Args:
        snapshot_id: 快照ID，或 "latest" 回滚到最近的

    Returns:
        快照中的配置数据，调用方需据此重建 shield
    """
    if snapshot_id == "latest":
        snaps = list_snapshots()
        if not snaps:
            return {"ok": False, "error": "No snapshots available"}
        snapshot_id = snaps[0]["id"]

    path = _snapshot_dir() / f"{snapshot_id}.json"
    if not path.exists():
        return {"ok": False, "error": f"Snapshot not found: {snapshot_id}"}

    data = json.loads(path.read_text(encoding="utf-8"))
    return {
        "ok": True,
        "id": data["id"],
        "timestamp": data["timestamp"],
        "reason": data.get("reason", ""),
        "config": data["config"],
        "learning_status": data.get("learning_status", {}),
    }


def _cleanup_old_snapshots(keep: int = 5):
    """保留最近 N 个快照，删除更旧的。"""
    files = sorted(_snapshot_dir().glob("snap_*.json"), reverse=True)
    for f in files[keep:]:
        try:
            f.unlink()
        except Exception:
            pass


def main():
    parser = argparse.ArgumentParser(
        description="道体·玄盾 配置快照管理 — 备份/回滚配置"
    )
    parser.add_argument("--backup", "-b", action="store_true",
                        help="创建当前配置的快照")
    parser.add_argument("--list", "-l", action="store_true",
                        help="列出所有快照")
    parser.add_argument("--restore", "-r", default=None,
                        help="回滚到指定快照（ID 或 'latest'）")
    parser.add_argument("--reason", default="manual",
                        help="备份原因（用于 --backup）")

    args = parser.parse_args()

    if args.list:
        snaps = list_snapshots()
        if not snaps:
            print("无快照记录")
            return
        print(f"共 {len(snaps)} 个快照：")
        for s in snaps:
            print(f"  {s['id']} | {s['timestamp']} | {s['reason']} | "
                  f"模式={s['mode']} 样本={s['sample_count']}")
        return

    if args.restore:
        result = restore_snapshot(args.restore)
        if result.get("ok"):
            print(f"已加载快照 {result['id']}（{result['timestamp']}）")
            print(f"原因: {result.get('reason', '')}")
            config = result["config"]
            print(f"配置参数: {len(config)} 项")
            print("关键参数:")
            for key in ["enable_observing_mode", "emergency_bypass",
                        "gray_deploy_ratio", "prototype_distance_threshold",
                        "structural_anomaly_threshold"]:
                if key in config:
                    print(f"  {key}: {config[key]}")
            print("\n请据此重建 XuanDun 实例以应用配置。")
        else:
            print(f"错误: {result.get('error', '未知错误')}", file=sys.stderr)
            sys.exit(1)
        return

    if args.backup:
        from ..xuandun import XuanDun
        from ..config import XuanDunConfig
        config = XuanDunConfig()
        shield = XuanDun(config=config)
        result = create_snapshot(shield, reason=args.reason)
        print(f"快照已创建: {result['id']}（{result['timestamp']}）")
        print(f"存储位置: {result['path']}")
        return

    parser.print_help()


if __name__ == "__main__":
    main()
