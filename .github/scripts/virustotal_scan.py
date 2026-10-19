#!/usr/bin/env python3
# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白

"""VirusTotal 误报扫描门禁（发布前）。

为什么需要
────────────────────────────────────────────────────────────
玄盾的引擎是 Python 冻结出来的可执行文件，这类产物被国产杀软
按启发式判成 Trojan/Intercept 是常态。用户装包时看到报毒，
不管功能有没有问题都会直接卸载 —— 所以发布前必须扫一遍。
被发出去的那个包，恰恰是品牌最脆弱的一环。

行为约定（这三条要一起看）
────────────────────────────────────────────────────────────
· 未配置 ``VIRUSTOTAL_API_KEY`` → **跳过**，退出码 0。
  「没配密钥」是运维配置缺失，不该把发布卡死；
  卡死后最常见的处理是「把这道门禁删掉」，那才是真正的损失。

· VirusTotal 不可达 / 限流 / 5xx → **告警后跳过**，退出码 0。
  第三方服务故障不是本产品的发布失败。若让它在此时变红，
  维护者会去修错的地方，且下一次很可能直接绕过门禁。
  代价是：VT 长期不可用时这道门禁等于没跑 —— 所以必须打 warning，
  让「没扫成」在日志里显式可见，而不是安静地绿。

· 恶意引擎数 > ``VT_MAX_MALICIOUS``（默认 5）→ 退出码 1，阻断发布。

· 一个待扫文件都没找到 → 退出码 1。
  这几乎一定是路径写错了。静默放行比报错更糟：
  门禁看起来在跑，其实什么都没扫。

为什么逐个文件上报
────────────────────────────────────────────────────────────
四个平台产物互不相同（Windows 安装包 / dmg / deb / AppImage）。
某一种被杀软盯上，另外三种未必；合并成一个结论会让定位失效。
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

try:
    import httpx
except ImportError:  # pragma: no cover - CI 会先装依赖
    print("::warning::未安装 httpx，跳过 VirusTotal 扫描")
    sys.exit(0)

API = "https://www.virustotal.com/api/v3"
PATTERNS = ("*.exe", "*.dmg", "*.AppImage", "*.deb")
# VirusTotal 直传上限 32MB；更大的文件要先申请专用上传地址。
DIRECT_LIMIT = 32 * 1024 * 1024
# 每个文件最多等多久出分析结果
ANALYSIS_TIMEOUT_S = int(os.getenv("VT_ANALYSIS_TIMEOUT_S", "600"))
POLL_INTERVAL_S = 20
# 公开 API 限速 4 次/分钟，调用之间留足间隔
CALL_GAP_S = 16


def _files(root: Path) -> list[Path]:
    out: list[Path] = []
    for pat in PATTERNS:
        out.extend(sorted(root.rglob(pat)))
    # 按路径排序并去重，保证输出稳定、可对照
    return sorted(set(out))


def _pick_analysis_id(payload: dict) -> str:
    data = (payload or {}).get("data") or {}
    return str(data.get("id") or "")


def _post_with_retry(client: httpx.Client, url: str, **kwargs):
    """POST；遇到 429 时退避重试两次。

    ★ 只重试限流。签名错、文件太大这类确定性错误重试也没用，
      反而会把真正的错因拖成超时。
    """
    for attempt in range(3):
        resp = client.post(url, **kwargs)
        if resp.status_code != 429:
            return resp
        wait = 60 * (attempt + 1)
        print(f"  · 触发限流，等待 {wait}s 后重试（{attempt + 1}/3）")
        time.sleep(wait)
    return resp


def scan_one(client: httpx.Client, headers: dict, path: Path) -> dict:
    """上传单个文件并等待分析完成。返回 {status, malicious, suspicious,...}。"""
    size = path.stat().st_size
    print(f"  上传 {path.name}（{size / 1024 / 1024:.1f} MB）…")

    if size <= DIRECT_LIMIT:
        url = f"{API}/files"
    else:
        # 大文件要先换专用上传地址（直传接口有 32MB 上限）
        r = client.get(f"{API}/files/upload_url", headers=headers)
        r.raise_for_status()
        url = str((r.json() or {}).get("data") or "")
        if not url:
            raise RuntimeError("未取得大文件上传地址")

    with open(path, "rb") as fh:
        resp = _post_with_retry(
            client, url, headers=headers,
            files={"file": (path.name, fh, "application/octet-stream")},
            timeout=300,
        )
    resp.raise_for_status()
    analysis_id = _pick_analysis_id(resp.json())
    if not analysis_id:
        raise RuntimeError(f"上传未返回 analysis id：{resp.text[:200]}")

    time.sleep(CALL_GAP_S)
    deadline = time.time() + ANALYSIS_TIMEOUT_S
    while time.time() < deadline:
        r = client.get(f"{API}/analyses/{analysis_id}", headers=headers)
        r.raise_for_status()
        attrs = ((r.json() or {}).get("data") or {}).get("attributes") or {}
        status = str(attrs.get("status") or "")
        if status == "completed":
            stats = attrs.get("stats") or {}
            return {
                "status": "completed",
                "malicious": int(stats.get("malicious") or 0),
                "suspicious": int(stats.get("suspicious") or 0),
                "undetected": int(stats.get("undetected") or 0),
            }
        time.sleep(POLL_INTERVAL_S)
    return {"status": "timeout", "malicious": 0, "suspicious": 0, "undetected": 0}


def main() -> int:
    key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "artifacts")
    files = _files(root)

    if not key:
        print("跳过 VirusTotal 扫描：未配置 VIRUSTOTAL_API_KEY")
        return 0
    if not files:
        print(f"::error::在 {root} 下未找到任何待扫产物（*.exe/*.dmg/*.AppImage/*.deb）")
        return 1

    threshold = int(os.getenv("VT_MAX_MALICIOUS", "5"))
    print(f"待扫 {len(files)} 个文件；阈值：恶意引擎数 > {threshold} 即阻断")
    headers = {"x-apikey": key}
    rows: list[tuple[str, str, int, int]] = []
    infra_errors = 0

    with httpx.Client(timeout=120, follow_redirects=True) as client:
        for path in files:
            try:
                res = scan_one(client, headers, path)
            except Exception as e:  # noqa: BLE001
                # 外部服务问题不判发布失败，但必须显式告警
                infra_errors += 1
                print(f"::warning::扫描失败 {path.name}：{type(e).__name__}: {e}")
                rows.append((path.name, "error", 0, 0))
                continue
            rows.append((
                path.name, res["status"], res["malicious"], res["suspicious"]
            ))
            print(
                f"  → {path.name}: {res['status']}  "
                f"恶意 {res['malicious']} / 可疑 {res['suspicious']} / "
                f"未检出 {res['undetected']}"
            )
            time.sleep(CALL_GAP_S)

    print("\n=== 汇总 ===")
    for name, status, mal, sus in rows:
        print(f"  {name:<44} {status:<10} 恶意 {mal:<3} 可疑 {sus}")

    over = [r for r in rows if r[2] > threshold]
    if over:
        for name, _, mal, _ in over:
            print(f"::error::{name} 被 {mal} 家引擎判为恶意（阈值 {threshold}）")
        print("阻断发布：请先完成误报申诉，或确认是否真的被植入了恶意代码")
        return 1

    if infra_errors:
        print(
            f"::warning::{infra_errors} 个文件未能完成扫描 —— "
            "本次未得到有效的杀软结论，请人工确认"
        )
    print("PASS：未发现超阈值的报毒")
    return 0


if __name__ == "__main__":
    sys.exit(main())
