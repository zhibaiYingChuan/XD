#!/usr/bin/env python3
# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白

"""启动物理产物，验证它**真的能跑**、且护栏在位。

★ 为什么必须有这份脚本（2026-10-30，本地实测）
────────────────────────────────────────────────────────────────
把打包器从 Nuitka 换成 PyInstaller 之后，原先的门禁
（`verify_guardrail_bundle.py`：在二进制里 grep 类名）**失效了** ——
PyInstaller 把纯 Python 模块压缩进 PYZ 归档，类名不以明文出现在
任何文件里，那条判据会对**好包**恒假。

更关键的是：grep 就算能过，也只能证明「字符串在」，不能证明
「模块导得进来」。本地实测到一个真实的静默降级：

    numpy 2.x 把实现搬进了 numpy._core，PyInstaller 的静态分析
    只看到 numpy 顶层包 → 产物照样启动、/health 照常 {"status":"ok"}，
    只有护栏在导入时报 No module named 'numpy._core._exceptions'
    → guardrail_missing_layers = ["system_prompt_inject","sensitive_leak"]
    → 提示词注入与敏感泄露两层检测全空，而界面显示「防护中」。

这种包能装、能开、能自检，用户在受攻击时才发现没有防护。
所以判据必须端到端：**把进程拉起来，问它自己**。

判据
────────────────────────────────────────────────────────────────
  ① 产物进程能在超时内起来，/health 返回 ok
  ② /api/state 的 guardrail_missing_layers 为空
  ③ 任何一步失败 → 非 0 退出，并在日志里写清「用户会看到什么」

用法
────────────────────────────────────────────────────────────────
    python verify_engine_runtime.py
    python verify_engine_runtime.py --root <引擎目录>   # 测试用
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DEFAULT_ENGINE_DIR = ROOT / "src-tauri" / "resources" / "engine"

# 启动到 /health 就绪的上限。CI 的冷启动（首次解包 + 建库）通常 < 15 秒，
# 60 秒是给慢盘/杀软实时扫描留的余量。
BOOT_TIMEOUT_S = 60

# 单次 HTTP 请求超时
HTTP_TIMEOUT_S = 5


def _free_port() -> int:
    """取一个空闲端口 —— 不能用引擎默认的 18765：
    CI 上可能已有别的实例，而「端口被占」会被误读成「产物坏了」。"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _find_engine(engine_dir: Path) -> Path:
    """找到 sidecar 主程序。

    ★ macOS / Linux 的 sidecar 没有扩展名（Tauri externalBin 约定），
      不能只认 .exe —— 那会让这两个平台在「找不到可执行文件」处失败，
      而那是判据写错，不是产物有问题。
    """
    candidates = [
        p for p in engine_dir.iterdir()
        if p.is_file() and p.name.startswith("xuandun-engine-")
    ]
    if not candidates:
        raise SystemExit(f"::error::引擎目录里没有 xuandun-engine-*：{engine_dir}")
    return candidates[0]


def _get(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=HTTP_TIMEOUT_S) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _wait_ready(port: int, proc: subprocess.Popen, deadline: float) -> dict:
    """轮询 /health 直到就绪；进程提前退出则立即失败。"""
    url = f"http://127.0.0.1:{port}/health"
    last_err = ""
    while time.time() < deadline:
        if proc.poll() is not None:
            raise SystemExit(
                f"::error::引擎进程启动后立即退出（退出码 {proc.returncode}）——"
                "产物缺依赖，或与当前系统不兼容"
            )
        try:
            data = _get(url)
            if data.get("status") == "ok":
                return data
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as e:
            last_err = str(e)
        time.sleep(0.5)
    raise SystemExit(f"::error::引擎在 {BOOT_TIMEOUT_S} 秒内没有就绪（最后一次错误：{last_err}）")


def main() -> int:
    engine_dir = DEFAULT_ENGINE_DIR
    if "--root" in sys.argv:
        idx = sys.argv.index("--root")
        try:
            engine_dir = Path(sys.argv[idx + 1])
        except IndexError:
            print("::error::--root 后面要跟一个目录", file=sys.stderr)
            return 2

    if not engine_dir.is_dir():
        print(f"::error::引擎目录不存在：{engine_dir}", file=sys.stderr)
        return 2

    exe = _find_engine(engine_dir)
    port = _free_port()

    # 独立的数据目录：绝不能写到用户/CI 的真实数据目录，
    # 否则这次验证会污染统计与许可证状态。
    data_dir = tempfile.mkdtemp(prefix="xuandun-verify-")
    env = dict(os.environ)
    env["XUANDUN_DATA_DIR"] = data_dir
    env["PYTHONIOENCODING"] = "utf-8"
    # 关掉代理：CI 上常有 http_proxy，会让 127.0.0.1 请求被绕出去。
    for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy",
              "ALL_PROXY", "all_proxy"):
        env.pop(k, None)
    env["NO_PROXY"] = "127.0.0.1,localhost"
    env["no_proxy"] = "127.0.0.1,localhost"

    print(f"启动产物：{exe}")
    print(f"  端口={port} 数据目录={data_dir}")

    kwargs = {}
    if sys.platform.startswith("win"):
        # 控制台程序也不弹窗；产物本身是 --noconsole
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)

    proc = subprocess.Popen(
        [str(exe), "--port", str(port)],
        env=env, cwd=str(engine_dir),
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        **kwargs,
    )

    try:
        deadline = time.time() + BOOT_TIMEOUT_S
        health = _wait_ready(port, proc, deadline)
        print(f"  /health: {health}")

        state = _get(f"http://127.0.0.1:{port}/api/state")
        missing = state.get("guardrail_missing_layers") or []
        print(f"  guardrail_missing_layers: {missing}")

        if missing:
            print("::error::护栏层缺失： " + "、".join(missing), file=sys.stderr)
            print(
                "::error::这个包能启动、能自检通过，但提示词注入与敏感泄露"
                "两类检测完全失效，而界面照常显示「防护中」。",
                file=sys.stderr,
            )
            print(
                "::error::常见原因：打包时漏收某个依赖的子模块"
                "（例如 numpy 2.x 的 numpy._core）。",
                file=sys.stderr,
            )
            return 1

        print("PASS：产物可运行，且护栏层在位（提示词注入 + 敏感泄露）")
        return 0
    finally:
        try:
            proc.terminate()
            proc.wait(timeout=10)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass


if __name__ == "__main__":
    sys.exit(main())
