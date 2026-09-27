# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白
# 本文件受道体研究许可证 v1.0 约束，禁止逆向工程和再分发

"""引擎可执行入口（由 Nuitka 编译）。

本文件刻意保持极简：Nuitka 静态分析入口脚本来收集依赖，
所有真实逻辑都在 daoti_xuandun_personal 包内。
"""

import sys


def main() -> int:
    # 保证冻结（frozen）模式下也能 import 到同目录的包
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        sys.path.insert(0, sys._MEIPASS)

    from daoti_xuandun_personal.proxy.app import run

    run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
