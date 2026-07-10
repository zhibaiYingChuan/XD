#!/usr/bin/env python3
# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白
# 本文件受道体研究许可证 v1.0 约束，禁止逆向工程和再分发
# 详见 LICENSE 文件

"""道体·玄盾 灰度监控脚本 — 采集引擎健康指标，输出 JSONL 日志。

用法:
  # 监控模式（持续运行）
  python scripts/graymon.py --engine http://127.0.0.1:18770 --interval 60 --output graymon.jsonl

  # 带异常告警
  python scripts/graymon.py --engine http://127.0.0.1:18770 --alert-webhook https://example.com/hook

  # 分析模式
  python scripts/graymon.py --analyze graymon.jsonl --summary
  python scripts/graymon.py --analyze graymon.jsonl --metric availability
  python scripts/graymon.py --analyze graymon.jsonl --metric latency
"""

import argparse
import json
import sys
import time
import statistics
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import urlopen, Request
from urllib.error import URLError


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def fetch_json(url: str, timeout: int = 10) -> dict:
    req = Request(url, method="GET")
    with urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def measure_latency(engine_url: str, timeout: int = 10) -> float:
    """发送测试 protect 请求测量延迟（毫秒）。"""
    test_payload = json.dumps({
        "text": "灰度监控探测请求 hello world",
        "session": "graymon",
        "mode": "balanced",
    }).encode("utf-8")
    req = Request(
        f"{engine_url}/protect",
        data=test_payload,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    start = time.monotonic()
    try:
        with urlopen(req, timeout=timeout) as resp:
            resp.read()
        elapsed_ms = (time.monotonic() - start) * 1000
        return round(elapsed_ms, 1)
    except Exception:
        return -1.0


def send_alert(webhook_url: str, alert_data: dict):
    """发送异常告警到 Webhook。"""
    payload = json.dumps(alert_data).encode("utf-8")
    req = Request(
        webhook_url,
        data=payload,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urlopen(req, timeout=10) as resp:
            resp.read()
    except Exception as e:
        print(f"[graymon] alert webhook failed: {e}", file=sys.stderr)


def probe_once(engine_url: str, measure_protect: bool = False) -> dict:
    """单次探测，返回指标字典。"""
    record = {
        "timestamp": utc_now(),
        "engine_health": "unknown",
        "engine_uptime": 0,
        "total_requests": 0,
        "total_blocked": 0,
        "block_rate": 0.0,
        "learning_mode": "unknown",
        "sample_count": 0,
        "latency_p50_ms": None,
        "latency_p95_ms": None,
        "latency_p99_ms": None,
        "alert": None,
    }

    try:
        health = fetch_json(f"{engine_url}/health", timeout=5)
        record["engine_health"] = health.get("status", "unknown")
    except Exception as e:
        record["engine_health"] = "down"
        record["alert"] = {"type": "engine_down", "message": str(e)}
        return record

    try:
        status = fetch_json(f"{engine_url}/status", timeout=5)
        record["engine_uptime"] = status.get("uptime", 0)
        record["total_requests"] = status.get("total_requests", 0)
        record["total_blocked"] = status.get("total_blocked", 0)
        record["block_rate"] = status.get("block_rate", 0.0)
        record["learning_mode"] = status.get("learning_mode", "unknown")
        record["sample_count"] = status.get("sample_count", 0)
    except Exception as e:
        record["alert"] = {"type": "status_fetch_failed", "message": str(e)}
        return record

    if measure_protect:
        latencies = []
        for _ in range(5):
            lat = measure_latency(engine_url)
            if lat > 0:
                latencies.append(lat)
            time.sleep(0.2)
        if latencies:
            latencies.sort()
            record["latency_p50_ms"] = round(statistics.median(latencies), 1)
            record["latency_p95_ms"] = round(latencies[-1], 1)
            record["latency_p99_ms"] = round(latencies[-1], 1)

    return record


def run_monitor(engine_url: str, interval: int, output_path: str,
                alert_webhook: str = "", latency_threshold: int = 500,
                measure_protect: bool = False):
    """持续监控循环。"""
    print(f"[graymon] 开始监控 {engine_url}，间隔 {interval}s", file=sys.stderr)
    if output_path:
        print(f"[graymon] 日志输出: {output_path}", file=sys.stderr)
    if alert_webhook:
        print(f"[graymon] 异常告警: {alert_webhook}", file=sys.stderr)

    out_file = open(output_path, "a", encoding="utf-8") if output_path else sys.stdout
    consecutive_failures = 0

    try:
        while True:
            record = probe_once(engine_url, measure_protect)

            if record["engine_health"] != "ok":
                consecutive_failures += 1
                if consecutive_failures >= 3:
                    record["alert"] = {
                        "type": "consecutive_failures",
                        "message": f"引擎连续 {consecutive_failures} 次探测失败",
                    }
            else:
                consecutive_failures = 0

            if record.get("latency_p95_ms") and record["latency_p95_ms"] > latency_threshold:
                record["alert"] = {
                    "type": "high_latency",
                    "message": f"P95延迟 {record['latency_p95_ms']}ms 超过阈值 {latency_threshold}ms",
                }

            line = json.dumps(record, ensure_ascii=False)
            out_file.write(line + "\n")
            out_file.flush()

            if record["alert"] and alert_webhook:
                send_alert(alert_webhook, {
                    "source": "graymon",
                    "timestamp": record["timestamp"],
                    "engine": engine_url,
                    **record["alert"],
                })

            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n[graymon] 监控已停止", file=sys.stderr)
    finally:
        if output_path and out_file is not sys.stdout:
            out_file.close()


def analyze_logs(log_path: str, metric: str = "", summary: bool = False, output: str = ""):
    """分析 JSONL 日志。"""
    records = []
    with open(log_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

    if not records:
        print("无日志记录", file=sys.stderr)
        return

    total = len(records)
    healthy = sum(1 for r in records if r.get("engine_health") == "ok")
    availability = (healthy / total * 100) if total else 0
    alerts = [r for r in records if r.get("alert")]

    latencies = [r["latency_p95_ms"] for r in records
                 if r.get("latency_p95_ms") and r["latency_p95_ms"] > 0]

    result = {
        "log_file": log_path,
        "total_records": total,
        "time_range": {
            "start": records[0].get("timestamp", ""),
            "end": records[-1].get("timestamp", ""),
        },
        "availability_pct": round(availability, 2),
        "healthy_count": healthy,
        "unhealthy_count": total - healthy,
        "alert_count": len(alerts),
        "alert_types": {},
        "latency_stats": {},
        "traffic_stats": {},
    }

    for r in alerts:
        atype = r["alert"].get("type", "unknown")
        result["alert_types"][atype] = result["alert_types"].get(atype, 0) + 1

    if latencies:
        result["latency_stats"] = {
            "count": len(latencies),
            "min_ms": round(min(latencies), 1),
            "max_ms": round(max(latencies), 1),
            "median_ms": round(statistics.median(latencies), 1),
            "mean_ms": round(statistics.mean(latencies), 1),
            "p95_ms": round(latencies[int(len(latencies) * 0.95)] if len(latencies) > 1 else latencies[0], 1),
        }

    if records:
        last = records[-1]
        first = records[0]
        result["traffic_stats"] = {
            "start_total_requests": first.get("total_requests", 0),
            "end_total_requests": last.get("total_requests", 0),
            "start_total_blocked": first.get("total_blocked", 0),
            "end_total_blocked": last.get("total_blocked", 0),
            "final_block_rate": last.get("block_rate", 0),
            "final_learning_mode": last.get("learning_mode", ""),
            "final_sample_count": last.get("sample_count", 0),
        }

    if metric == "availability":
        print(f"可用率: {availability:.2f}% ({healthy}/{total})")
        print(f"异常次数: {total - healthy}")
        print(f"告警次数: {len(alerts)}")
        for atype, count in result["alert_types"].items():
            print(f"  {atype}: {count}次")
    elif metric == "latency":
        if latencies:
            stats = result["latency_stats"]
            print(f"延迟统计 ({stats['count']} 次采样):")
            print(f"  最小: {stats['min_ms']}ms")
            print(f"  最大: {stats['max_ms']}ms")
            print(f"  中位数: {stats['median_ms']}ms")
            print(f"  平均: {stats['mean_ms']}ms")
            print(f"  P95: {stats['p95_ms']}ms")
        else:
            print("无延迟数据（未启用 --measure-protect）")
    elif summary or not metric:
        print(json.dumps(result, ensure_ascii=False, indent=2))

    if output:
        with open(output, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        print(f"\n报告已保存到: {output}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description="道体·玄盾 灰度监控脚本")
    parser.add_argument("--engine", default="http://127.0.0.1:18770", help="引擎地址")
    parser.add_argument("--interval", type=int, default=60, help="探测间隔（秒）")
    parser.add_argument("--output", default="", help="日志输出路径（JSONL）")
    parser.add_argument("--alert-webhook", default="", help="异常告警 Webhook URL")
    parser.add_argument("--latency-threshold", type=int, default=500, help="延迟告警阈值（ms）")
    parser.add_argument("--measure-protect", action="store_true", help="发送测试请求测量保护接口延迟")
    parser.add_argument("--analyze", metavar="LOG_FILE", help="分析模式：读取 JSONL 日志")
    parser.add_argument("--metric", choices=["availability", "latency"], help="分析模式下的专项指标")
    parser.add_argument("--summary", action="store_true", help="输出汇总报告")
    args = parser.parse_args()

    if args.analyze:
        analyze_logs(args.analyze, metric=args.metric, summary=args.summary, output=args.output)
    else:
        run_monitor(
            engine_url=args.engine,
            interval=args.interval,
            output_path=args.output,
            alert_webhook=args.alert_webhook,
            latency_threshold=args.latency_threshold,
            measure_protect=args.measure_protect,
        )


if __name__ == "__main__":
    main()
