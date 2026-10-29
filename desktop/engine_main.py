# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白
# 本文件受道体研究许可证 v1.0 约束，禁止逆向工程和再分发

"""引擎可执行入口（由 PyInstaller 打包，也可被 Nuitka 编译）。

本文件刻意保持极简：所有真实逻辑都在 daoti_xuandun_personal 包内。

★ 为什么这里要处理文件日志（2026-10-30）
────────────────────────────────────────────────────────────────
Windows 上打包时用的是 ``--noconsole``（引擎是后台服务，不能弹黑框），
此时 Python 的 stdout/stderr 是空的 —— 一旦启动阶段抛异常，
**任何输出都留不下来**：

    CI 上只看到「进程启动后立即退出（退出码 1）」，
    缺哪个库、哪一行崩的，全丢。

这既让发布链难以诊断，也让用户排障时拿不到线索。
这里增加一个显式开关：设置环境变量 ``XUANDUN_LOG_FILE`` 时，
把根 logger 同时写到该文件（不动任何默认行为）。
"""

import logging
import os
import sys


def _setup_file_logging() -> None:
    """按需把日志同时写入文件（仅当 XUANDUN_LOG_FILE 被设置）。"""
    path = (os.environ.get("XUANDUN_LOG_FILE") or "").strip()
    if not path:
        return
    try:
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        handler = logging.FileHandler(path, encoding="utf-8")
        handler.setFormatter(
            logging.Formatter(
                "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
            )
        )
        root = logging.getLogger()
        root.setLevel(logging.INFO)
        root.addHandler(handler)
    except Exception:
        # 日志落盘失败绝不能影响启动本身
        pass


def main() -> int:
    _setup_file_logging()

    # 保证冻结（frozen）模式下也能 import 到同目录的包
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        sys.path.insert(0, sys._MEIPASS)

    from daoti_xuandun_personal.proxy.app import run

    run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
