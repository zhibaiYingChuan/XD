# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白
# 本文件受道体研究许可证 v1.0 约束，禁止逆向工程和再分发
# 详见 LICENSE 文件

"""玄盾 AI 安全网关 — FastAPI 应用（T01 + T08/T11/T12）。

技术栈（POC 结论）：FastAPI + uvicorn + httpx.AsyncClient(stream=True)
- waitress 同步 WSGI 无法透传 SSE（hop-by-hop header 限制）
- POC 验证 FastAPI 路径可正常流式透传

端点清单：
- GET  /health            健康检查（T01 验收）
- POST /v1/chat/completions  OpenAI 兼容反向代理入口（T04）
- GET  /v1/models         OpenAI 兼容模型列表（T11，不含密钥）
- GET  /api/stats/realtime  实时统计快照（T10）
- GET  /api/config/safe     配置安全视图（不含密钥）

启动方式：
    uvicorn daoti_xuandun.gateway.app:app --host 0.0.0.0 --port 18765
"""

from __future__ import annotations

import logging
import os
import time
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

from .config import ConfigManager, ConfigLoadError
from .errors import (
    BlockedByShieldError,
    GatewayError,
    ModelDisabledError,
    NoRouteError,
    UpstreamHttpError,
    UpstreamTimeoutError,
    UpstreamUnreachableError,
    build_error_body,
)
from .proxy import ReverseProxy

logger = logging.getLogger("xuandun-gateway-app")

# 网关启动时间
_START_TIME = time.time()

# 全局配置管理器与反向代理
_config_manager: ConfigManager | None = None
_reverse_proxy: ReverseProxy | None = None


def _get_config_manager() -> ConfigManager:
    global _config_manager
    if _config_manager is None:
        raise RuntimeError("配置管理器尚未初始化")
    return _config_manager


def _get_reverse_proxy() -> ReverseProxy:
    global _reverse_proxy
    if _reverse_proxy is None:
        raise RuntimeError("反向代理尚未初始化")
    return _reverse_proxy


def init_gateway(config_path: str) -> None:
    """初始化网关（配置加载 + 反向代理创建）。

    Args:
        config_path: models.yaml 配置文件路径
    """
    global _config_manager, _reverse_proxy

    _config_manager = ConfigManager(config_path)
    _config_manager.load()
    _reverse_proxy = ReverseProxy(_config_manager)
    logger.info(
        "网关初始化完成: config=%s", config_path
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    """FastAPI lifespan 事件（startup + shutdown）。

    替代已弃用的 @app.on_event("startup")。
    """
    # startup
    config_path = os.environ.get(
        "XUANDUN_CONFIG_PATH",
        "config/models.yaml",
    )
    try:
        init_gateway(config_path)
    except ConfigLoadError as e:
        logger.error("网关配置加载失败，服务无法启动: %s", e)
        raise

    _get_config_manager().start_watching()
    logger.info("玄盾 AI 安全网关启动完成")

    yield

    # shutdown
    _get_config_manager().stop_watching()
    await _get_reverse_proxy().close()
    logger.info("玄盾 AI 安全网关已关闭")


app = FastAPI(
    title="玄盾 AI 安全网关",
    description="多模型 AI 安全网关 — 反向代理模式（Sprint 2b MVP）",
    version="1.3.0",
    lifespan=lifespan,
)


# ──────────────────────────────────────────────────────────────
# 健康检查（T01 验收：端口 18765 可访问 /health）
# ──────────────────────────────────────────────────────────────
@app.get("/health")
async def health() -> dict[str, Any]:
    """健康检查端点。

    G-18 修复：区分三种状态，避免 Docker healthcheck 假阳性。
    - ok: 配置已加载 + >=1 个 enabled 模型
    - degraded: 配置已加载但 0 个 enabled 模型
    - unhealthy: 配置未加载

    返回字段：status / version / uptime / models_count
    供 Docker/K8s healthcheck 与桌面端探活使用。
    Docker healthcheck 应仅 status=="ok" 视为健康。
    """
    config_loaded = False
    models_count = 0
    try:
        config = _get_config_manager().current_config
        config_loaded = True
        models_count = len(config.get_enabled_models())
    except RuntimeError:
        # 配置管理器尚未初始化
        config_loaded = False
    except Exception:
        config_loaded = False

    if not config_loaded:
        status = "unhealthy"
    elif models_count == 0:
        status = "degraded"
    else:
        status = "ok"

    return {
        "status": status,
        "version": "1.3.0",
        "uptime": int(time.time() - _START_TIME),
        "models_count": models_count,
    }


# ──────────────────────────────────────────────────────────────
# OpenAI 兼容：/v1/models（T11，不含密钥）
# ──────────────────────────────────────────────────────────────
@app.get("/v1/models")
async def list_models() -> dict[str, Any]:
    """OpenAI 兼容的模型列表端点。

    返回 enabled 模型列表，绝不包含密钥信息。
    """
    config = _get_config_manager().current_config
    safe_view = config.to_safe_view()

    # OpenAI 协议格式
    models_list = []
    for m in safe_view["models"]:
        if m["enabled"]:
            models_list.append({
                "id": m["id"],
                "object": "model",
                "created": int(_START_TIME),
                "owned_by": m["provider"],
                "xuandun": {
                    "display_name": m["display_name"],
                    "key_configured": m["key_configured"],
                    "fallback": m["fallback"],
                    "timeout_seconds": m["timeout_seconds"],
                },
            })

    return {"object": "list", "data": models_list}


# ──────────────────────────────────────────────────────────────
# OpenAI 兼容：/v1/chat/completions（T04 反向代理入口）
# ──────────────────────────────────────────────────────────────
@app.post("/v1/chat/completions")
async def chat_completions(request: Request):
    """OpenAI 兼容反向代理入口。

    流程（A-11 修正）：
    1. 接收请求 → 提取 model 字段
    2. 路由引擎匹配 → 确定目标模型
    3. 读取目标模型的 security 配置
    4. 按配置决定是否调用检测
    5. 检测通过 → 转发到后端模型
    6. 检测命中 → 阴阳门拦截（403）
    """
    # 解析请求体
    try:
        body_bytes = await request.body()
        import json
        request_body = json.loads(body_bytes) if body_bytes else {}
    except json.JSONDecodeError as e:
        return JSONResponse(
            status_code=400,
            content=build_error_body(
                message=f"请求体 JSON 解析失败: {e}",
                error_type="bad_request",
                code="invalid_json",
            ),
        )

    if not isinstance(request_body, dict):
        return JSONResponse(
            status_code=400,
            content=build_error_body(
                message="请求体必须是 JSON 对象",
                error_type="bad_request",
            ),
        )

    stream = request_body.get("stream", False)
    proxy = _get_reverse_proxy()

    try:
        status_code, json_body, stream_gen, headers = (
            await proxy.handle_chat_completions(request_body)
        )
    except BlockedByShieldError as e:
        # 安全检测拦截（403）
        logger.info("请求被拦截: %s", e.error_body["error"]["message"])
        return JSONResponse(
            status_code=e.status_code,
            content=e.error_body,
            headers=e.headers,
        )
    except NoRouteError as e:
        logger.warning("无路由匹配: %s", e.error_body["error"]["message"])
        return JSONResponse(
            status_code=e.status_code,
            content=e.error_body,
            headers=e.headers,
        )
    except ModelDisabledError as e:
        logger.warning("模型不可用: %s", e.error_body["error"]["message"])
        return JSONResponse(
            status_code=e.status_code,
            content=e.error_body,
            headers=e.headers,
        )
    except UpstreamTimeoutError as e:
        logger.warning("上游超时: %s", e.error_body["error"]["message"])
        return JSONResponse(
            status_code=e.status_code,
            content=e.error_body,
            headers=e.headers,
        )
    except UpstreamUnreachableError as e:
        logger.warning("上游不可达: %s", e.error_body["error"]["message"])
        return JSONResponse(
            status_code=e.status_code,
            content=e.error_body,
            headers=e.headers,
        )
    except UpstreamHttpError as e:
        # 上游 HTTP 错误（含密钥失效特殊处理）
        logger.warning(
            "上游 HTTP 错误: status=%s, body=%s",
            e.status_code, e.error_body["error"]["message"]
        )
        return JSONResponse(
            status_code=e.status_code,
            content=e.error_body,
            headers=e.headers,
        )
    except GatewayError as e:
        logger.error("网关错误: %s", e, exc_info=True)
        return JSONResponse(
            status_code=e.status_code,
            content=e.error_body,
            headers=e.headers,
        )
    except Exception as e:
        logger.error("未预期异常: %s", e, exc_info=True)
        return JSONResponse(
            status_code=500,
            content=build_error_body(
                message=f"网关内部错误: {type(e).__name__}",
                error_type="xuandun_internal",
            ),
        )

    # 成功响应
    if stream:
        # 流式响应
        return StreamingResponse(
            stream_gen,
            media_type="text/event-stream",
            headers=headers,
        )
    else:
        # 非流式响应
        return JSONResponse(
            status_code=status_code,
            content=json_body,
            headers=headers,
        )


# ──────────────────────────────────────────────────────────────
# 网关管理 API（T10 统计 + 配置安全视图）
# ──────────────────────────────────────────────────────────────
@app.get("/api/stats/realtime")
async def stats_realtime() -> dict[str, Any]:
    """实时统计快照（T10 按模型维度请求计数）。

    Sprint 3 db.rs schema 迁移后写入持久化存储，
    Sprint 2b 仅内存统计。
    """
    proxy = _get_reverse_proxy()
    stats_list = proxy.get_stats_snapshot()

    # 按模型维度聚合
    by_model: dict[str, dict[str, Any]] = {}
    for s in stats_list:
        mid = s["model_id"]
        if mid not in by_model:
            by_model[mid] = {
                "total": 0,
                "blocked": 0,
                "forwarded": 0,
                "error": 0,
                "timeout": 0,
                "cancelled": 0,  # G-04 修复：客户端断连统计
                "fallback_used": 0,
                "bytes_forwarded": 0,
            }
        agg = by_model[mid]
        agg["total"] += 1
        if s["status"] in agg:
            agg[s["status"]] += 1
        if s.get("fallback_used"):
            agg["fallback_used"] += 1
        agg["bytes_forwarded"] += s.get("bytes_forwarded", 0)

    return {
        "uptime": round(time.time() - _START_TIME, 1),
        "total_requests": len(stats_list),
        "by_model": by_model,
        "recent": stats_list[-50:],
    }


@app.get("/api/config/safe")
async def config_safe_view() -> dict[str, Any]:
    """配置安全视图（不含密钥，供桌面端展示）。"""
    config = _get_config_manager().current_config
    return config.to_safe_view()


# ──────────────────────────────────────────────────────────────
# 全局异常处理（T12 故障快速失败）
# ──────────────────────────────────────────────────────────────
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """全局异常处理：任何未捕获异常返回 503 + 明确错误体（T12）。"""
    logger.error(
        "未捕获异常: %s %s -> %s",
        request.method, request.url.path, exc,
        exc_info=True,
    )
    return JSONResponse(
        status_code=503,
        content=build_error_body(
            message=f"网关故障快速失败: {type(exc).__name__}",
            error_type="xuandun_internal",
            hint="服务可能不可用，请稍后重试或检查配置",
        ),
    )


def main():
    """uvicorn 启动入口。

    启动方式：
        python -m daoti_xuandun.gateway.app
        或
        uvicorn daoti_xuandun.gateway.app:app --host 0.0.0.0 --port 18765
    """
    import argparse

    # 编码一致性保护（Windows 环境）
    import sys
    if sys.platform == "win32":
        try:
            sys.stdout.reconfigure(encoding="utf-8")
            sys.stderr.reconfigure(encoding="utf-8")
        except Exception:
            pass

    parser = argparse.ArgumentParser(description="玄盾 AI 安全网关")
    parser.add_argument("--host", type=str, default="0.0.0.0",
                        help="监听地址（默认 0.0.0.0，服务器端反向代理）")
    parser.add_argument("--port", type=int, default=18765,
                        help="监听端口（默认 18765）")
    parser.add_argument("--config", type=str, default="config/models.yaml",
                        help="models.yaml 配置文件路径")
    parser.add_argument("--log-level", type=str, default="info",
                        choices=["debug", "info", "warning", "error"])
    args = parser.parse_args()

    # 通过环境变量传递配置路径给 lifespan
    os.environ["XUANDUN_CONFIG_PATH"] = args.config

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper()),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    import uvicorn
    uvicorn.run(
        "daoti_xuandun.gateway.app:app",
        host=args.host,
        port=args.port,
        log_level=args.log_level,
        # 生产环境建议 workers>1，但 Sprint 2b MVP 单 worker
        workers=1,
    )


if __name__ == "__main__":
    main()
