# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白
# 本文件受道体研究许可证 v1.0 约束，禁止逆向工程和再分发
# 详见 LICENSE 文件

"""道体·玄盾 FastAPI 集成模块。

使用方式：
    from daoti_xuandun.integrations.fastapi import XuanDunGuard

    guard = XuanDunGuard(level="STANDARD")

    @guard.protect
    @app.post("/chat")
    async def chat(request: ChatRequest):
        ...

活性防护哲学：集成应零侵入——一个装饰器即可启用防护，
无需修改业务逻辑。被拒绝的请求自动返回403，
调试信息通过响应头传递（不暴露算法细节）。
"""

from functools import wraps
from typing import Callable, Optional

from daoti_xuandun.config import DefenseLevel, XuanDunConfig
from daoti_xuandun.xuandun import XuanDun


class XuanDunGuard:
    """FastAPI 集成守卫：一个装饰器为API端点添加活性防护。

    Args:
        level: 防御层级 ("BASIC"/"STANDARD"/"STRICT"/"PARANOID")。
        config: 自定义配置（与level互斥，优先使用）。
        input_field: 请求体中要检查的字段名（默认 "message"）。
        debug: 是否在响应头中包含调试信息。
    """

    def __init__(
        self,
        level: str = "STANDARD",
        config: Optional[XuanDunConfig] = None,
        input_field: str = "message",
        debug: bool = False,
        on_reject: Optional[Callable] = None,
    ):
        if config is not None:
            self.config = config
        else:
            defense_level = DefenseLevel[level]
            self.config = XuanDunConfig.for_level(defense_level)
        self.config.debug = debug
        self.xuandun = XuanDun(self.config)
        self.input_field = input_field
        self.debug = debug
        self.on_reject = on_reject

    def protect(self, func: Callable) -> Callable:
        """装饰器：为API端点添加活性防护。

        被拒绝的请求自动返回403，调试信息通过响应头传递。
        """
        @wraps(func)
        async def wrapper(*args, **kwargs):
            request_body = kwargs.get("request_body", kwargs.get("body", None))
            if request_body is None:
                for arg in args:
                    if hasattr(arg, self.input_field):
                        request_body = arg
                        break

            text = None
            if request_body is not None:
                if isinstance(request_body, dict):
                    text = request_body.get(self.input_field)
                elif hasattr(request_body, self.input_field):
                    text = getattr(request_body, self.input_field)
                elif isinstance(request_body, str):
                    text = request_body

            if text is None:
                return await func(*args, **kwargs)

            result = self.xuandun.protect(text, session_id="api")

            if not result.allowed:
                if self.on_reject is not None:
                    custom_response = self.on_reject(text, result)
                    if custom_response is not None:
                        return custom_response

                from fastapi import HTTPException
                headers = {}
                if self.debug and result.debug_info:
                    headers["X-Debug-Familiarity"] = result.debug_info.get(
                        "domain_familiarity", "unknown"
                    )
                    headers["X-Debug-Reason"] = result.debug_info.get(
                        "decision_reason", "unknown"
                    )
                raise HTTPException(
                    status_code=403,
                    detail="Input rejected by security guard",
                    headers=headers if headers else None,
                )

            return await func(*args, **kwargs)

        return wrapper

    def check(self, text: str, session_id: str = "api") -> dict:
        """直接检查输入，返回结构化结果（不抛异常）。

        适用于非装饰器场景，如中间件或流式处理。
        """
        result = self.xuandun.protect(text, session_id=session_id)
        response = {
            "allowed": result.allowed,
            "trust_level": result.trust_level.value if hasattr(result.trust_level, 'value') else str(result.trust_level),
        }
        if self.debug and result.debug_info:
            response["debug"] = result.debug_info
        return response
