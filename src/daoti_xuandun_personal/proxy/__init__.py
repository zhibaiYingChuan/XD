# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白
# 本文件受道体研究许可证 v1.0 约束，禁止逆向工程和再分发
# 详见 LICENSE 文件

"""个人版本地代理包。

三层检测管道：
- sanitizer.py：第一层 请求侧脱敏
- verifier.py：第二层 响应侧完整性验证
- restorer.py：第三层 脱敏内容恢复
- app.py：FastAPI 代理入口
- relay.py：请求转发 + SSE 流式透传
"""

from .app import create_app, run
from .restorer import ContentRestorer
from .sanitizer import RequestSanitizer
from .verifier import ResponseVerifier

__all__ = [
    "create_app",
    "run",
    "RequestSanitizer",
    "ResponseVerifier",
    "ContentRestorer",
]
