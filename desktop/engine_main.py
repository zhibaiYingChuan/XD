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

import faulthandler
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


def _ensure_std_streams() -> None:
    """兜底 sys.stdout / sys.stderr，防止 ``--noconsole`` 下为 None。

    ★★ 2026-10-30 CI 实测（Windows 专属，Linux/macOS 不出现）：
       Windows 打包用 ``--noconsole``（引擎是后台服务，不能弹黑框），
       PyInstaller 在该模式下把 ``sys.stdout`` / ``sys.stderr`` 置为 ``None``。
       于是链路上**任何一处 print()** 都会抛

           AttributeError: 'NoneType' object has no attribute 'write'

       而异常若发生在启动早期、又被某个库吞掉，表现就是
       「进程活着、端口不监听、日志空白」—— 正是我们观测到的形态。

       这里给两个流一个指向 devnull 的真实文件对象：既不会崩，
       也不会往任何地方喷输出。文件日志由 _setup_file_logging 负责。
    """
    for name in ("stdout", "stderr"):
        if getattr(sys, name, "missing") is None:
            try:
                setattr(sys, name, open(os.devnull, "w", encoding="utf-8"))
            except OSError:
                pass


def _setup_stack_dump() -> None:
    """启动后定期把线程栈 dump 到文件，用于诊断「进程活着但卡住」。

    ★★ 2026-10-30 CI 实测（仅 Windows）：engine.log 停在
       「calling run()...」之后再无输出，进程一直活着、端口始终不监听。
       这不是异常（异常有 traceback），而是**卡住** —— 没有栈就无从判断
       卡在 config 加载、还是 uvicorn 绑定。
       faulthandler 是标准库，能在不打断进程的前提下定时把调用栈写下来。
    """
    path = (os.environ.get("XUANDUN_LOG_FILE") or "").strip()
    if not path:
        return
    try:
        stack_path = os.path.join(
            os.path.dirname(os.path.abspath(path)), "engine_stack.txt"
        )
        fh = open(stack_path, "w", encoding="utf-8")
        # 45 秒后第一次 dump，之后每 30 秒一次（CI 的超时是 150 秒）
        faulthandler.dump_traceback_later(45, repeat=True, file=fh)
    except Exception:
        pass


def main() -> int:
    _ensure_std_streams()
    _setup_file_logging()
    _setup_stack_dump()

    log = logging.getLogger("xuandun-engine")
    # 启动标记：File 日志为空时，至少能区分「没进来」与「进来了但卡住」。
    log.info(
        "engine_main start: frozen=%s meipass=%s argv=%s",
        getattr(sys, "frozen", False), getattr(sys, "_MEIPASS", ""), sys.argv,
    )

    # 保证冻结（frozen）模式下也能 import 到同目录的包
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        sys.path.insert(0, sys._MEIPASS)

    log.info("importing daoti_xuandun_personal...")
    from daoti_xuandun_personal.proxy.app import run

    log.info("calling run()...")
    try:
        run()
    except BaseException:
        # ★ stderr 在 --noconsole 下是 devnull，异常会彻底消失。
        #   这里必须显式记进文件日志，否则 CI 上只剩「进程退出了」。
        log.exception("run() 抛出异常，引擎无法启动")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
