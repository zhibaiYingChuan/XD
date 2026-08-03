# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白
# 本文件受道体研究许可证 v1.0 约束，禁止逆向工程和再分发
# 详见 LICENSE 文件

"""玄盾 AI 安全网关 — 反向代理核心（T04 + T07/T09/T10/T12）。

实现 OpenAI 协议反向代理：
1. 接收请求 → 提取 model 字段
2. 路由引擎匹配 → 确定目标模型（A-11 修正）
3. 读取目标模型的 security 配置
4. 按配置决定是否调用检测
5. 检测通过 → 转发到后端模型
6. 检测命中 → 阴阳门拦截（403）

技术栈（POC 结论）：FastAPI + uvicorn + httpx.AsyncClient(stream=True)
- waitress 同步 WSGI 无法透传 SSE（hop-by-hop header 限制）
- 必须使用异步方案

三层超时控制（A-25）：
- connect=5s
- read=300s（或模型配置 timeout_seconds）
- total=模型配置 timeout_seconds

基础故障转移（A-09r，Sprint 2b 仅单一 fallback 链）：
- 主模型超时/5xx 时切 fallback 模型
- 单次重试，不形成环
- Sprint 3 做完整故障转移（熔断+多级链+降级）

错误传播规范（A-24）：
- 流式已开始：用 SSE error event 后关闭流
- 流式未开始：用 HTTP 状态码 + JSON 错误体
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any, AsyncGenerator

import httpx

from .config import ConfigManager
from .errors import (
    BlockedByShieldError,
    GatewayError,
    ModelDisabledError,
    NoRouteError,
    UpstreamHttpError,
    UpstreamTimeoutError,
    UpstreamUnreachableError,
    build_error_body,
    build_sse_error_event,
    build_upstream_error_body,
    map_status_for_upstream_error,
    should_disable_retry,
)
from .schema import ModelConfig
from .security import get_security_checker

logger = logging.getLogger("xuandun-gateway-proxy")

# 三层超时默认值（A-25）
DEFAULT_CONNECT_TIMEOUT = 5.0
DEFAULT_READ_TIMEOUT = 300.0
DEFAULT_WRITE_TIMEOUT = 30.0
DEFAULT_POOL_TIMEOUT = 60.0


def _build_httpx_timeout(total_seconds: int) -> httpx.Timeout:
    """构造三层超时配置。

    connect=5s / read=模型配置 / total=模型配置（A-25）
    """
    return httpx.Timeout(
        connect=DEFAULT_CONNECT_TIMEOUT,
        read=float(total_seconds),
        write=DEFAULT_WRITE_TIMEOUT,
        pool=DEFAULT_POOL_TIMEOUT,
    )


def _resolve_api_key(model_config: ModelConfig) -> str:
    """从环境变量读取模型 API Key（A-08）。

    密钥通过 XUANDUN_MODEL_<ID>_KEY 环境变量注入，
    绝不存明文，绝不返回客户端。
    """
    import os
    return os.environ.get(model_config.backend.api_key_env, "")


class RequestStats:
    """单次请求统计（T10 按模型维度请求计数埋点）。"""

    def __init__(self, model_id: str, request_model: str | None):
        self.model_id = model_id
        self.request_model = request_model
        self.start_time = time.time()
        self.first_byte_time: float | None = None
        self.end_time: float | None = None
        self.status: str = "pending"  # pending/blocked/forwarded/error/timeout
        self.upstream_status: int | None = None
        self.bytes_forwarded: int = 0
        self.fallback_used: bool = False
        self.error_type: str | None = None

    def mark_first_byte(self) -> None:
        if self.first_byte_time is None:
            self.first_byte_time = time.time()

    def mark_end(self, status: str) -> None:
        self.end_time = time.time()
        self.status = status

    def to_log_dict(self) -> dict[str, Any]:
        """转为日志记录字典（T10，前置 schema 兼容）。

        Sprint 3 db.rs schema 迁移后写入 stats_model_hourly 表。
        """
        duration = (self.end_time or time.time()) - self.start_time
        ttft = (
            (self.first_byte_time - self.start_time)
            if self.first_byte_time
            else None
        )
        return {
            "model_id": self.model_id,
            "request_model": self.request_model,
            "timestamp": self.start_time,
            "duration_seconds": round(duration, 3),
            "ttft_seconds": round(ttft, 3) if ttft else None,
            "status": self.status,
            "upstream_status": self.upstream_status,
            "bytes_forwarded": self.bytes_forwarded,
            "fallback_used": self.fallback_used,
            "error_type": self.error_type,
        }


class ReverseProxy:
    """反向代理核心。

    使用 httpx.AsyncClient 流式透传 OpenAI SSE 响应。
    共享 httpx 客户端连接池，配置热加载时重建。
    """

    def __init__(self, config_manager: ConfigManager):
        self._config_manager = config_manager
        self._http_client: httpx.AsyncClient | None = None
        self._stats_log: list[dict[str, Any]] = []
        self._stats_lock = __import__("threading").Lock()
        # 待关闭的旧客户端列表（G-15 修复：热加载时异步 aclose 旧客户端，避免 socket 泄漏）
        self._pending_close_clients: list[httpx.AsyncClient] = []

        # 注册热加载回调：重建 httpx 客户端
        config_manager.add_reload_callback(self._on_config_reload)

    async def _get_http_client(self) -> httpx.AsyncClient:
        """获取 httpx 客户端（懒初始化）。

        G-15 修复：如果存在待关闭的旧客户端，先 await aclose() 完成，
        避免高频热加载导致 socket 句柄泄漏（EMFILE）。
        """
        # 先清理待关闭的旧客户端
        if self._pending_close_clients:
            for old in self._pending_close_clients:
                try:
                    await old.aclose()
                    logger.debug("旧 httpx 客户端已 aclose")
                except Exception as e:
                    logger.warning("旧 httpx 客户端 aclose 异常: %s", e)
            self._pending_close_clients.clear()

        if self._http_client is None:
            self._http_client = httpx.AsyncClient(
                http2=True,
                limits=httpx.Limits(
                    max_connections=100,
                    max_keepalive_connections=20,
                ),
                timeout=_build_httpx_timeout(300),
            )
            logger.info("httpx.AsyncClient 已创建（http2=true）")
        return self._http_client

    def _on_config_reload(self, new_config) -> None:
        """配置热加载回调：标记客户端需重建。

        G-15 修复：旧客户端加入待关闭列表，下次请求时 await aclose()。
        不在此处直接 await（回调是同步的），避免阻塞 watchdog 线程。
        """
        old_client = self._http_client
        self._http_client = None
        if old_client is not None:
            # 加入待关闭列表，下次 _get_http_client 时清理
            self._pending_close_clients.append(old_client)
            logger.info("配置热加载，旧 httpx 客户端加入待关闭列表")

    async def close(self) -> None:
        """关闭 httpx 客户端（应用关闭时调用）。"""
        if self._http_client is not None:
            await self._http_client.aclose()
            self._http_client = None
            logger.info("httpx.AsyncClient 已关闭")

    def _record_stats(self, stats: RequestStats) -> None:
        """记录请求统计（T10）。"""
        with self._stats_lock:
            self._stats_log.append(stats.to_log_dict())
            # 保留最近 10000 条
            if len(self._stats_log) > 10000:
                self._stats_log = self._stats_log[-5000:]

    def get_stats_snapshot(self) -> list[dict[str, Any]]:
        """获取统计快照（供 /api/stats/realtime 使用）。"""
        with self._stats_lock:
            return list(self._stats_log)

    async def handle_chat_completions(
        self, request_body: dict
    ) -> tuple[int, dict | None, AsyncGenerator[bytes, None] | None, dict[str, str]]:
        """处理 /v1/chat/completions 请求。

        Returns:
            (status_code, json_body, stream_generator, headers)
            - 流式：status=200, json_body=None, stream=generator
            - 非流式：status=200, json_body=响应, stream=None
            - 错误：status=错误码, json_body=错误体, stream=None
        """
        config = self._config_manager.current_config
        request_model = request_body.get("model")
        stream = request_body.get("stream", False)

        # 1. 路由匹配（A-11 修正）
        target_model, match_reason = config.resolve_route(request_model)
        if target_model is None:
            raise NoRouteError(request_model)

        if not target_model.enabled:
            raise ModelDisabledError(target_model.id, "disabled or key missing")

        stats = RequestStats(target_model.id, request_model)
        logger.info(
            "请求路由: request_model=%s -> target=%s (%s), stream=%s",
            request_model, target_model.id, match_reason, stream,
        )

        # 2. 安全检测（A-11 修正：路由后读取模型 security 配置）
        checker = get_security_checker()
        try:
            await checker.check_request(target_model, request_body)
        except BlockedByShieldError:
            stats.mark_end("blocked")
            stats.error_type = "blocked_by_shield"
            self._record_stats(stats)
            raise

        # 3. 转发到后端模型（含基础故障转移 T07）
        try:
            return await self._forward_request(
                target_model, request_body, stream, stats
            )
        except (UpstreamTimeoutError, UpstreamUnreachableError, UpstreamHttpError) as e:
            # 基础故障转移（A-09r，Sprint 2b 仅单一 fallback 链）
            if target_model.fallback is not None:
                fallback_model = config.get_model(target_model.fallback)
                if (
                    fallback_model is not None
                    and fallback_model.enabled
                    and fallback_model.id != target_model.id
                ):
                    logger.warning(
                        "主模型 %s 失败 (%s)，切 fallback %s",
                        target_model.id, type(e).__name__, fallback_model.id,
                    )
                    stats.fallback_used = True
                    # fallback 不再递归 fallback，避免环
                    fallback_no_chain = fallback_model.model_copy(
                        update={"fallback": None}
                    )
                    return await self._forward_request(
                        fallback_no_chain, request_body, stream, stats
                    )
            raise

    async def _forward_request(
        self,
        model_config: ModelConfig,
        request_body: dict,
        stream: bool,
        stats: RequestStats,
    ) -> tuple[int, dict | None, AsyncGenerator[bytes, None] | None, dict[str, str]]:
        """转发请求到后端模型。

        三层超时控制（A-25）：connect=5s / read=模型配置 / total=模型配置
        """
        client = await self._get_http_client()
        api_key = _resolve_api_key(model_config)
        if not api_key:
            stats.mark_end("error")
            stats.error_type = "key_missing"
            self._record_stats(stats)
            raise ModelDisabledError(
                model_config.id, "API key not configured"
            )

        # 构造后端请求
        backend_url = (
            f"{model_config.backend.base_url.rstrip('/')}/chat/completions"
        )
        # 替换 model 为后端实际模型名
        forward_body = dict(request_body)
        forward_body["model"] = model_config.backend.model

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        }

        timeout = _build_httpx_timeout(model_config.timeout_seconds)

        try:
            if not stream:
                # 非流式：直接转发
                resp = await client.post(
                    backend_url,
                    json=forward_body,
                    headers=headers,
                    timeout=timeout,
                )
                stats.upstream_status = resp.status_code
                stats.bytes_forwarded = len(resp.content)
                # G-22 修复：2xx 全部视为成功，仅 >=400 视为错误
                is_success = 200 <= resp.status_code < 300
                stats.mark_end("forwarded" if is_success else "error")
                self._record_stats(stats)

                if resp.status_code >= 400:
                    raise UpstreamHttpError(
                        resp.status_code, resp.content
                    )

                # 2xx 成功：校验响应体是否为 JSON（G-23 修复：防止 HTML 劫持误判）
                try:
                    json_body = resp.json()
                except Exception as json_err:
                    content_type = resp.headers.get("content-type", "")
                    if "application/json" not in content_type:
                        logger.warning(
                            "模型 %s 上游返回非 JSON 响应 (Content-Type: %s)，可能被 CDN 劫持",
                            model_config.id, content_type,
                        )
                        raise UpstreamUnreachableError(
                            f"上游返回非 JSON 响应，可能被 CDN 劫持 (Content-Type: {content_type})"
                        ) from json_err
                    raise

                return (
                    200,
                    json_body,
                    None,
                    {"X-XuanDun-Model": model_config.id},
                )

            # 流式：httpx.AsyncClient.stream() 逐 chunk 透传
            return await self._forward_stream(
                client, backend_url, forward_body, headers, timeout,
                model_config, stats,
            )

        except httpx.ConnectTimeout as e:
            logger.warning(
                "模型 %s 连接超时: %s", model_config.id, e
            )
            stats.mark_end("timeout")
            stats.error_type = "connect_timeout"
            self._record_stats(stats)
            raise UpstreamTimeoutError("connect") from e
        except httpx.ReadTimeout as e:
            logger.warning(
                "模型 %s 读取超时: %s", model_config.id, e
            )
            stats.mark_end("timeout")
            stats.error_type = "read_timeout"
            self._record_stats(stats)
            raise UpstreamTimeoutError("read") from e
        except httpx.ConnectError as e:
            logger.warning(
                "模型 %s 不可达: %s", model_config.id, e
            )
            stats.mark_end("error")
            stats.error_type = "connect_error"
            self._record_stats(stats)
            raise UpstreamUnreachableError(
                f"上游不可达: {model_config.backend.base_url}"
            ) from e
        except httpx.HTTPError as e:
            logger.error(
                "模型 %s HTTP 异常: %s", model_config.id, e, exc_info=True
            )
            stats.mark_end("error")
            stats.error_type = "http_error"
            self._record_stats(stats)
            raise UpstreamUnreachableError(str(e)) from e

    async def _forward_stream(
        self,
        client: httpx.AsyncClient,
        backend_url: str,
        forward_body: dict,
        headers: dict[str, str],
        timeout: httpx.Timeout,
        model_config: ModelConfig,
        stats: RequestStats,
    ) -> tuple[int, dict | None, AsyncGenerator[bytes, None] | None, dict[str, str]]:
        """流式转发：httpx.AsyncClient.stream() 逐 chunk 透传。

        错误传播规范（A-24）：
        - 流式已开始：用 SSE error event 后关闭流
        - 流式未开始：用 HTTP 状态码
        """

        async def stream_generator() -> AsyncGenerator[bytes, None]:
            """异步逐 chunk 透传上游 SSE 流。

            G-04 修复：捕获 asyncio.CancelledError（客户端断连），
            确保上游请求被取消（async with 自动 aclose），避免 socket 泄漏与 token 浪费。
            """
            stream_started = False
            try:
                async with client.stream(
                    "POST",
                    backend_url,
                    json=forward_body,
                    headers=headers,
                    timeout=timeout,
                ) as upstream:
                    # G-22 修复：2xx 全部视为成功，仅 >=400 视为错误
                    if upstream.status_code >= 400:
                        stats.upstream_status = upstream.status_code
                        stats.mark_end("error")
                        stats.error_type = f"upstream_{upstream.status_code}"
                        self._record_stats(stats)
                        # 读取错误体
                        err_body = await upstream.aread()
                        # 通过异常抛出，由上层处理
                        raise UpstreamHttpError(
                            upstream.status_code, err_body
                        )

                    # 流式开始：逐 chunk 透传
                    stats.upstream_status = upstream.status_code
                    async for chunk in upstream.aiter_bytes():
                        if chunk:
                            if not stream_started:
                                stream_started = True
                                stats.mark_first_byte()
                                logger.debug(
                                    "模型 %s 流式开始 (TTFT=%.3fs)",
                                    model_config.id,
                                    stats.first_byte_time - stats.start_time,
                                )
                            stats.bytes_forwarded += len(chunk)
                            yield chunk

                    stats.mark_end("forwarded")
                    self._record_stats(stats)
                    logger.info(
                        "模型 %s 流式完成: %d bytes, %.3fs",
                        model_config.id,
                        stats.bytes_forwarded,
                        (stats.end_time or time.time()) - stats.start_time,
                    )

            except asyncio.CancelledError:
                # G-04 修复：客户端断开连接，记录 cancelled 状态
                # async with 已自动 aclose 上游请求，避免 socket 泄漏
                logger.info(
                    "模型 %s 流式被客户端取消（CancelledError），上游请求已自动取消",
                    model_config.id,
                )
                stats.mark_end("cancelled")
                stats.error_type = "client_cancelled"
                self._record_stats(stats)
                # 不再 re-raise，让流式正常结束
                raise
            except UpstreamHttpError:
                # 流式未开始的上游错误，向上传播
                raise
            except httpx.ReadTimeout as e:
                logger.warning(
                    "模型 %s 流式读取超时: %s", model_config.id, e
                )
                stats.mark_end("timeout")
                stats.error_type = "read_timeout"
                self._record_stats(stats)
                if stream_started:
                    # 流式已开始：发送 SSE error event 后关闭
                    err_body = build_error_body(
                        message="上游读取超时，流中断",
                        error_type="upstream_timeout",
                        code="upstream_read_timeout",
                    )
                    yield build_sse_error_event(err_body)
                else:
                    raise UpstreamTimeoutError("read") from e
            except httpx.ConnectError as e:
                logger.warning(
                    "模型 %s 流式连接失败: %s", model_config.id, e
                )
                stats.mark_end("error")
                stats.error_type = "connect_error"
                self._record_stats(stats)
                if stream_started:
                    err_body = build_error_body(
                        message="上游连接中断",
                        error_type="upstream_unreachable",
                    )
                    yield build_sse_error_event(err_body)
                else:
                    raise UpstreamUnreachableError(str(e)) from e
            except Exception as e:
                logger.error(
                    "模型 %s 流式异常: %s",
                    model_config.id, e, exc_info=True,
                )
                stats.mark_end("error")
                stats.error_type = "stream_error"
                self._record_stats(stats)
                if stream_started:
                    err_body = build_error_body(
                        message=f"流式传输异常: {type(e).__name__}",
                        error_type="stream_error",
                    )
                    yield build_sse_error_event(err_body)
                else:
                    raise UpstreamUnreachableError(str(e)) from e

        return (
            200,
            None,
            stream_generator(),
            {
                "X-XuanDun-Model": model_config.id,
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
            },
        )
