# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白
# 本文件受道体研究许可证 v1.0 约束，禁止逆向工程和再分发
# 详见 LICENSE 文件

"""个人版本地代理入口（FastAPI）。

三层检测管道在 `/v1/chat/completions` 上完整串联：
    请求 → 【第一层】脱敏 → 转发中转站 → 【第二层】响应验证
          → 【第三层】恢复脱敏 → 返回用户

管理 API（供桌面端 UI 调用）：
    GET  /api/state          当前防护状态（首页状态栏）
    GET  /api/stats          今日统计（首页 KPI）
    GET  /api/logs           日志列表
    GET  /api/relays         中转站信誉列表
    GET/PUT /api/config      配置读写
    POST /api/pause          暂停防护
    GET  /health             健康检查
"""

from __future__ import annotations

import json
import logging
import time
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator, Dict, List, Optional, Tuple

import httpx
from fastapi import Body, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse

from ..config import PersonalConfig
from ..reputation.tracker import ReputationTracker
from ..storage.db import PersonalStorage
from ..types import Action, LogEntry, LogType, RedactionRecord, SecurityLevel
from .baseline import build_baseline
from .restorer import ContentRestorer
from .sanitizer import RequestSanitizer
from .verifier import ResponseVerifier

logger = logging.getLogger("xuandun-personal.app")

# 流式响应中期验证阈值（字节）
STREAM_VERIFY_THRESHOLD = 8192

# 全局单例（lifespan 初始化）
_config: Optional[PersonalConfig] = None
_storage: Optional[PersonalStorage] = None
_sanitizer: Optional[RequestSanitizer] = None
_verifier: Optional[ResponseVerifier] = None
_restorer: Optional[ContentRestorer] = None
_reputation: Optional[ReputationTracker] = None
_http_client: Optional[httpx.AsyncClient] = None
_paused_until: float = 0.0     # 暂停截止时间戳


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """应用生命周期。"""
    global _config, _storage, _sanitizer, _verifier, _restorer, _reputation, _http_client

    # ① 加载配置
    _config = PersonalConfig.load()
    _config.apply_env_overrides()

    # ② 初始化组件
    _storage = PersonalStorage()
    _sanitizer = RequestSanitizer(
        level=_config.guard.security_level,
        custom_keywords=_config.guard.custom_keywords,
    )
    for cat, enabled in _config.guard.enabled_categories.items():
        _sanitizer.set_category_enabled(cat, enabled)

    _verifier = ResponseVerifier(
        level=_config.guard.security_level,
        enable_pattern_check=_config.guard.enable_pattern_check,
    )
    _restorer = ContentRestorer()
    _reputation = ReputationTracker()

    # ★ P2-10 修复：原实现只写不读，lifespan 从未调用 load_reputations()，
    #   导致信誉数据纯驻内存、重启即丢，首页「当前中转站」显示未配置空态。
    for rep in _storage.load_reputations():
        _reputation.import_reputation(rep)

    # ③ HTTP 客户端
    timeout_s = _config.server.request_timeout_s
    _http_client = httpx.AsyncClient(
        timeout=httpx.Timeout(
            connect=10.0, read=timeout_s, write=30.0, pool=10.0
        ),
        limits=httpx.Limits(max_connections=50, max_keepalive_connections=20),
        follow_redirects=False,      # ★ 安全：不自动跟随中转站重定向
    )

    logger.info(
        "个人版代理就绪: http://%s:%d → %s",
        _config.server.host, _config.server.port, _config.relay.base_url or "(未配置)",
    )

    yield

    # ④ 清理
    if _http_client is not None:
        await _http_client.aclose()
        _http_client = None
    if _storage is not None:
        _storage.close()
        _storage = None
    logger.info("个人版代理已关闭")


def create_app() -> FastAPI:
    """创建 FastAPI 应用。"""
    app = FastAPI(
        title="道体·玄盾 个人版",
        description="保护个人用户在使用 AI 中转站时的数据安全",
        version="0.1.0-alpha",
        lifespan=lifespan,
        docs_url="/docs",
    )

    # CORS：仅允许本地桌面端（tauri://localhost / http://localhost:1420）
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "tauri://localhost",
            "http://tauri.localhost",
            "http://localhost:1420",
            "http://127.0.0.1:1420",
        ],
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE"],
        allow_headers=["Content-Type", "Authorization"],
    )

    # ══════════════════════════════════════════════════════════
    # 中转站代理端点
    # ══════════════════════════════════════════════════════════

    @app.post("/v1/chat/completions")
    async def chat_completions(request: Request):
        """OpenAI 兼容代理端点（三层检测管道）。"""
        if _config is None or _storage is None:
            raise HTTPException(status_code=503, detail="代理未就绪")

        # 解析请求体
        try:
            body = await request.json()
        except json.JSONDecodeError:
            raise HTTPException(status_code=400, detail="请求体不是合法 JSON")

        session_id = request.headers.get("X-Session-Id") or "default"
        model = body.get("model", "")
        stream = bool(body.get("stream", False))
        upstream_domain = _reputation.extract_domain(_config.relay.base_url) if _reputation else ""

        # 防护已暂停 → 直通
        if time.time() < _paused_until:
            return await _relay_passthrough(body, stream, session_id)

        # ══════ 第一层：请求侧脱敏 ══════
        redaction_records = []
        if _config.guard.enable_request_sanitize and _sanitizer is not None:
            # ★ v0.1.0 重写为单次逐条处理。
            #   旧实现先把全部消息拼成一个 combined 脱敏、再整体写回
            #   最后一条 user 消息，产生三个实际故障：
            #     ① system prompt 与历史轮次被静默丢弃 —— 中转站收到的
            #        请求结构与用户发出的完全不同，而这种结构篡改
            #        本该是我们要检测的，却由我们自己在转发前做掉了；
            #     ② 占位符长度 ≠ 原值长度，用 combined 的偏移量去切
            #        已替换的文本必然错位，实测把 assistant 消息切成两半；
            #     ③ 同一段内容被重复发送（拼接结果含全部历史 + 本轮）。
            #   逐条处理后每条的 offsets 都相对自身，彻底消除偏移问题，
            #   且只需扫描一次（BLOCK 由 _BlockRequest 异常上抛）。
            try:
                redaction_records = _sanitize_messages_inplace(
                    body, _sanitizer
                )
            except _BlockRequest as blocked:
                entry = LogEntry(
                    log_type=LogType.REQUEST_SANITIZE.value,
                    relay_domain=upstream_domain,
                    action=Action.BLOCK.value,
                    severity="high",
                    model=model,
                    summary=blocked.reason,
                    detail_json=json.dumps(
                        {"hit_categories": blocked.categories},
                        ensure_ascii=False,
                    ),
                )
                log_id = _storage.insert_log(entry)
                # ★ P2-13：阻断路径也记 total_calls，否则首页
                #   「今日已检查 N 次」失真、KPI 数字对不上
                _storage.update_daily_stats(total_calls=1, danger=1)
                logger.info(
                    "会话 %s 请求被阻断：%s", session_id, blocked.reason
                )
                return JSONResponse(
                    status_code=403,
                    content={
                        "error": {
                            "type": "sensitive_data_blocked",
                            "message": blocked.reason,
                            "log_id": log_id,
                        }
                    },
                )

            if redaction_records:
                logger.info(
                    "会话 %s 请求脱敏 %d 处",
                    session_id, len(redaction_records),
                )

        # 登记脱敏记录供第三层恢复
        restore_session = _restorer.begin_session(session_id) if _restorer else session_id
        if _restorer and redaction_records:
            _restorer.register(restore_session, redaction_records)

        # ══════ 请求基线（★ v0.1.0）══════
        # 必须在转发前捕获，且必须在 _forward_to_relay 覆盖 model 之前 ——
        # 否则基线里的 model 会被我们自己改写的值污染，
        # 「模型降级」判据就永远发现不了真正的降级。
        request_baseline = build_baseline(body)
        if _storage is not None:
            try:
                _storage.save_request_baseline(
                    session_id, **request_baseline.to_storage_kwargs()
                )
            except Exception as e:  # noqa: BLE001 — 基线失败不阻断转发
                logger.warning("请求基线写入失败: %s", e)

        # ══════ 转发到中转站 ══════
        t0 = time.time()
        try:
            upstream_response = await _forward_to_relay(body, stream)
        except httpx.TimeoutException:
            return _proxy_error(upstream_domain, model, session_id,
                                "中转站响应超时", t0, LogType.PROXY_ERROR)
        except httpx.HTTPError as e:
            return _proxy_error(upstream_domain, model, session_id,
                                f"无法连接中转站：{e}", t0, LogType.PROXY_ERROR)

        latency_ms = (time.time() - t0) * 1000

        # ══════ 第二层 + 第三层 ══════
        if stream:
            return await _handle_stream(
                upstream_response, session_id, restore_session,
                upstream_domain, model, latency_ms, redaction_records,
                request_baseline,
            )
        return await _handle_non_stream(
            upstream_response, session_id, restore_session,
            upstream_domain, model, latency_ms, redaction_records,
            request_baseline,
        )

    async def _forward_to_relay(body: Dict[str, Any], stream: bool):
        """转发请求到中转站。"""
        if _http_client is None or _config is None:
            raise httpx.ConnectError("代理未初始化")

        # 覆盖模型名
        payload = dict(body)
        if _config.relay.model:
            payload["model"] = _config.relay.model

        return await _http_client.post(
            f"{_config.relay.normalized_base}/chat/completions",
            json=payload,
            headers={
                "Authorization": f"Bearer {_config.relay.api_key}",
                "Content-Type": "application/json",
            },
        )

    async def _relay_passthrough(body: Dict[str, Any], stream: bool, session_id: str):
        """防护暂停时的直通转发。"""
        try:
            upstream = await _forward_to_relay(body, stream)
        except httpx.HTTPError as e:
            return JSONResponse(
                status_code=502,
                content={"error": {"message": f"中转站不可达：{e}", "type": "upstream_error"}},
            )
        # ★ P2-17 修复：LogType.RELAY（正常转发）原先在整个代码库中
        #   从未被产生，导致日志页「正常转发」筛选项恒为空 ——
        #   一个用户看得见、却永远无结果的选项。防护暂停期间正是
        #   「未经检测的转发」，如实记录反而是透明度要求。
        _record_log(
            LogType.RELAY.value,
            _reputation.extract_domain(_config.relay.base_url) if _reputation else "",
            Action.PASS.value,
            "low",
            str(body.get("model", "")),
            [],
            None,
            session_id,
            [],
            text_preview="防护已暂停，本次请求未经检测直接转发",
        )
        if stream:
            return StreamingResponse(
                upstream.aiter_bytes(),
                status_code=upstream.status_code,
                media_type="text/event-stream",
            )
        return JSONResponse(status_code=upstream.status_code, content=upstream.json())

    # ══════════════════════════════════════════════════════════
    # 非流式响应处理
    # ══════════════════════════════════════════════════════════

    async def _handle_non_stream(
        upstream, session_id, restore_session,
        domain, model, latency_ms, redaction_records,
        request_baseline=None,
    ):
        """非流式响应：验证 → 恢复 → 返回。"""
        try:
            payload = upstream.json()
        except json.JSONDecodeError:
            payload = {"raw": upstream.text}

        content = _extract_content(payload)

        # 第二层：响应验证（★ 传入请求基线做结构差分）
        verify_result = None
        if _config.guard.enable_response_verify and _verifier is not None:
            verify_result = _verifier.verify(
                content, session_id, payload, baseline=request_baseline
            )

        # 记录中转站返回的模型名（供事后比对模型降级）
        if _storage is not None and isinstance(payload, dict):
            try:
                _storage.record_response_model(
                    session_id, str(payload.get("model", "") or "")
                )
            except Exception:  # noqa: BLE001
                pass

        # 合并中转站篡改占位符的异常
        anomalies: List[Any] = []
        if _restorer is not None:
            restored_content, restore_anomalies = _restorer.restore(
                restore_session, content
            )
            if restore_anomalies:
                anomalies.extend(restore_anomalies)
                content = restored_content
                _set_content(payload, restored_content)
            _restorer.clear_after_response(restore_session)
            _storage.clear_redactions_for_session(restore_session)

        # 合并所有发现项
        findings = list(verify_result.findings) if verify_result else []
        findings.extend(anomalies)
        max_sev = _max_severity(findings)
        # ★ v0.1.0 修复缺口 7：原实现 action 只取 verify_result，
        #   不含 restore anomalies。而 restorer 产出的
        #   placeholder_injection 是 severity="high"，却因
        #   action=="pass" 不阻断、还被记为 safe ——
        #   一个 high 级发现被计入「今日安全」，信誉分也不受影响。
        #   现在按合并后的最高严重度重新走一次级别映射。
        action = _resolve_action(max_sev, verify_result)

        # 高危阻断
        if max_sev == "high" and action == Action.BLOCK.value:
            _record_log(
                LogType.RESPONSE_VERIFY, domain, Action.BLOCK.value, "high",
                model, findings, payload, session_id, redaction_records,
                text_preview=content,
            )
            _record_reputation(domain, Action.BLOCK.value, latency_ms, content)
            return JSONResponse(
                status_code=502,
                content={
                    "error": {
                        "type": "relay_response_blocked",
                        "message": findings[0].detail if findings else "响应含高危内容，已阻断",
                        "findings": [f.to_dict() for f in findings],
                    }
                },
            )

        # 正常返回
        _record_log(
            LogType.RESPONSE_VERIFY, domain, action, max_sev,
            model, findings, payload, session_id, redaction_records,
            text_preview=content,
        )
        _record_reputation(domain, action, latency_ms, content)
        return JSONResponse(status_code=upstream.status_code, content=payload)

    # ══════════════════════════════════════════════════════════
    # 流式响应处理
    # ══════════════════════════════════════════════════════════

    async def _handle_stream(
        upstream, session_id, restore_session,
        domain, model, latency_ms, redaction_records,
        request_baseline=None,
    ):
        """流式响应（SSE）。

        流式的安全权衡：
        - **不逐 chunk 验证**（会破坏流式体验且难以在首字节前判定）
        - 采用**累计缓冲 + 阈值触发**：缓冲到 8KB 时做一次中期验证
        - **流结束时对全文再验证一次**（覆盖短响应，修复「<8KB 零验证」缺陷）
        - **第三层脱敏恢复在流结束时对累积内容执行**（修复占位符原样透传）
        - 验证到高危 → 发送 SSE error event 后关闭流
        """
        findings: List[Any] = []
        collected: List[str] = []
        total_len = 0
        mid_verified = False
        state = {"blocked": False}
        last_verified_len = 0

        async def _generator() -> AsyncGenerator[bytes, None]:
            nonlocal total_len, mid_verified, last_verified_len
            try:
                async for chunk in upstream.aiter_bytes():
                    if state["blocked"]:
                        break

                    # 累积文本用于验证与恢复
                    try:
                        text = chunk.decode("utf-8", errors="ignore")
                    except Exception:  # noqa: BLE001
                        text = ""
                    if text:
                        collected.append(text)
                        total_len += len(text)

                    yield chunk

                    # 累计到 8KB 后做一次中期验证
                    if (
                        not mid_verified
                        and total_len >= STREAM_VERIFY_THRESHOLD
                        and _config.guard.enable_response_verify
                        and _verifier is not None
                    ):
                        joined = "".join(collected)
                        result = _verifier.verify(
                            _extract_sse_content(joined), session_id, None
                        )
                        findings.extend(result.findings)
                        if result.action == Action.BLOCK.value and result.severity == "high":
                            state["blocked"] = True
                            # 发送 SSE error 事件后关闭流
                            error_payload = {
                                "error": {
                                    "type": "relay_response_blocked",
                                    "message": result.findings[0].detail
                                    if result.findings else "响应含高危内容",
                                }
                            }
                            yield (
                                "data: " + json.dumps(error_payload, ensure_ascii=False) + "\n\n"
                            ).encode("utf-8")
                            break
                        mid_verified = True

                # ★ 流结束：对全文做最终验证 + 第三层脱敏恢复
                if not state["blocked"]:
                    full = "".join(collected)
                    sse_text, sse_tools, sse_model = _extract_sse_frames(full)

                    # 记录中转站返回的模型（供模型降级比对）
                    if _storage is not None and sse_model:
                        try:
                            _storage.record_response_model(session_id, sse_model)
                        except Exception:  # noqa: BLE001
                            pass

                    if _restorer is not None and _restorer.has_placeholders(full):
                        restored, anomalies = _restorer.restore(restore_session, full)
                        if anomalies:
                            findings.extend(anomalies)
                        if restored != full:
                            findings.extend(_verify_restored_text(
                                restored, session_id, _verifier
                            ))

                    # ★ v0.1.0 修复缺口 4：原实现的中期验证是
                    #   「全长只做一次」（mid_verified 单标志），
                    #   且流结束时的补偿验证条件是 `not mid_verified` ——
                    #   于是 >8KB 的流在第 8KB 之后完全不再接受检测，
                    #   注释说的「流结束时对全文再验证一次」与实现相反。
                    #   现在改为：只要有新增内容就再验一次（滑动复核），
                    #   并以全文做最终判定，覆盖中转站在流尾追加载荷的情况。
                    grown = total_len > last_verified_len
                    if (
                        _config.guard.enable_response_verify
                        and _verifier is not None
                        and (not mid_verified or grown)
                    ):
                        result = _verifier.verify(
                            sse_text,
                            session_id,
                            {"tool_calls": sse_tools, "model": sse_model}
                            if (sse_tools or sse_model) else None,
                            baseline=request_baseline,
                        )
                        if result.findings:
                            findings.extend(result.findings)
                        if (
                            result.action == Action.BLOCK.value
                            and result.severity == "high"
                        ):
                            state["blocked"] = True
                            error_payload = {
                                "error": {
                                    "type": "relay_response_blocked",
                                    "message": result.findings[0].detail
                                    if result.findings else "响应含高危内容",
                                }
                            }
                            yield (
                                "data: " + json.dumps(
                                    error_payload, ensure_ascii=False
                                ) + "\n\n"
                            ).encode("utf-8")
                        mid_verified = True
                        last_verified_len = total_len
            finally:
                # 流结束后的收尾（无论正常/异常结束都执行）
                if _restorer is not None:
                    _restorer.clear_after_response(restore_session)
                if _storage is not None:
                    _storage.clear_redactions_for_session(restore_session)
                joined = "".join(collected)
                severity = _max_severity(findings)
                # ★ 与非流式路径统一：按合并后的最高严重度决定处置，
                #   而不是「有 findings 就一律 ALERT」——
                #   否则流式下 high 级发现永远不会被记为 BLOCK，
                #   信誉分的 danger_count 也就永远不涨。
                action = (
                    Action.BLOCK.value
                    if state["blocked"]
                    else _resolve_action(severity, None)
                )
                if findings and action == Action.PASS.value:
                    action = Action.ALERT.value
                _record_log(
                    LogType.RESPONSE_VERIFY, domain, action, severity,
                    model, findings, None, session_id, redaction_records,
                    text_preview=joined,
                )
                _record_reputation(domain, action, latency_ms, joined)

        return StreamingResponse(
            _generator(),
            status_code=upstream.status_code,
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
            },
        )

    # ══════════════════════════════════════════════════════════
    # 管理 API
    # ══════════════════════════════════════════════════════════

    @app.get("/health")
    async def health():
        """健康检查。"""
        return {
            "status": "ok",
            "version": app.version,
            "guard_ready": _verifier is not None,
            "relay_configured": bool(_config and _config.relay.base_url),
        }

    @app.get("/api/state")
    async def get_state():
        """当前防护状态（首页状态栏）。"""
        if _config is None or _storage is None:
            return {"state": "learning", "message": "初始化中"}

        # 暂停状态
        if time.time() < _paused_until:
            remain = int(_paused_until - time.time())
            return {
                "state": "paused",
                "message": f"防护已暂停，剩余 {remain // 60} 分 {remain % 60} 秒",
                "paused_remaining_s": remain,
            }

        # 今日统计
        today = _storage.get_today_stats()
        if today["danger_count"] > 0:
            state = "danger"
            message = f"今日已阻断 {today['danger_count']} 次危险响应"
        elif today["suspect_count"] > 0:
            state = "suspect"
            message = f"今日发现 {today['suspect_count']} 次可疑响应"
        elif today["total_calls"] == 0:
            state = "learning"
            message = "等待第一次请求..."
        else:
            state = "protecting"
            message = f"今日已检查 {today['total_calls']} 次请求"

        return {
            "state": state,
            "message": message,
            "security_level": _config.guard.security_level,
            "upstream": _config.relay.name,
            "today": today,
        }

    @app.get("/api/stats")
    async def get_stats(days: int = Query(7, ge=1, le=90)):
        """统计（首页 KPI + 趋势图）。"""
        if _storage is None:
            return {"today": {}, "recent": []}
        return {
            "today": _storage.get_today_stats(),
            "recent": _storage.get_recent_stats(days),
        }

    @app.get("/api/logs")
    async def get_logs(
        limit: int = Query(50, ge=1, le=500),
        offset: int = Query(0, ge=0),
        log_type: Optional[str] = None,
        action: Optional[str] = None,
        search: Optional[str] = None,
        days: Optional[int] = Query(None, ge=1, le=365),
    ):
        """日志列表。`days` 用于文档 4.1 要求的「今天」筛选。"""
        if _storage is None:
            return {"entries": [], "total": 0}
        start_ts = time.time() - days * 86400 if days else None
        entries = _storage.query_logs(
            limit=limit, offset=offset, log_type=log_type,
            action=action, search=search, start_ts=start_ts,
        )
        return {
            "entries": [e.to_dict() for e in entries],
            "total": _storage.count_logs(
                log_type=log_type, action=action, start_ts=start_ts
            ),
        }

    @app.get("/api/logs/{log_id}")
    async def get_log_detail(log_id: int):
        """日志详情（含脱敏记录）。"""
        if _storage is None:
            raise HTTPException(status_code=503, detail="存储未就绪")
        # ★ P2-14 修复：原实现遍历最近 1000 条做线性匹配（含一段死循环），
        #   既低效又有 1000 条截断缺陷。现改为 SQL 精确定位。
        entry = _storage.get_log(log_id)
        if entry is None:
            raise HTTPException(status_code=404, detail="日志不存在")
        return {
            "entry": entry.to_dict(),
            "redactions": _storage.get_redactions(log_id),
        }

    @app.post("/api/logs/{log_id}/mark-safe")
    async def mark_log_safe(log_id: int):
        """标记日志为误报（文档 4.1「标记为安全」）。"""
        if _storage is None:
            raise HTTPException(status_code=503, detail="存储未就绪")
        if _storage.get_log(log_id) is None:
            raise HTTPException(status_code=404, detail="日志不存在")
        _storage.mark_safe(log_id)
        logger.info("日志 %d 已标记为误报", log_id)
        return {"ok": True, "log_id": log_id, "marked_safe": True}

    @app.post("/api/logs/export")
    async def export_logs(payload: Dict[str, Any] = Body(default={})):
        """导出日志为 CSV / JSON（文档 4.1「导出」按钮）。"""
        if _storage is None:
            raise HTTPException(status_code=503, detail="存储未就绪")
        fmt = str((payload or {}).get("format", "csv")).lower()
        limit = int((payload or {}).get("limit", 10_000))
        limit = max(1, min(limit, 50_000))

        entries = _storage.get_all_for_export(limit=limit)
        stamp = time.strftime("%Y%m%d-%H%M%S")

        if fmt == "json":
            return {
                "ok": True,
                "filename": f"xuandun-logs-{stamp}.json",
                "content": json.dumps(
                    [e.to_dict() for e in entries],
                    ensure_ascii=False,
                    indent=2,
                ),
            }

        # CSV（带 BOM 保证 Excel 正确识别 UTF-8 中文）
        header = [
            "id", "time", "type", "relay_domain", "model", "action",
            "severity", "marked_safe", "finding_count", "summary", "text_preview",
        ]
        lines = [",".join(header)]
        for e in entries:
            import datetime as _dt
            ts = _dt.datetime.fromtimestamp(e.timestamp).strftime("%Y-%m-%d %H:%M:%S")
            row = [
                str(e.id), ts, e.log_type, e.relay_domain, e.model, e.action,
                e.severity, "1" if e.marked_safe else "0",
                str(e.finding_count), e.summary, e.text_preview,
            ]
            lines.append(",".join(_csv_escape(v) for v in row))
        return {
            "ok": True,
            "filename": f"xuandun-logs-{stamp}.csv",
            "content": "﻿" + "\n".join(lines),
        }

    @app.delete("/api/logs/{log_id}")
    async def delete_log(log_id: int):
        """删除单条日志。"""
        if _storage is None:
            raise HTTPException(status_code=503, detail="存储未就绪")
        if not _storage.delete_log(log_id):
            raise HTTPException(status_code=404, detail="日志不存在")
        return {"ok": True, "log_id": log_id}

    @app.post("/api/logs/clear")
    async def clear_logs(before_days: int = Body(0, embed=True)):
        """清空日志。"""
        if _storage is None:
            raise HTTPException(status_code=503, detail="存储未就绪")
        before_ts = time.time() - before_days * 86400 if before_days > 0 else None
        count = _storage.clear_logs(before_ts)
        return {"ok": True, "deleted": count}

    @app.get("/api/relays")
    async def list_relays():
        """中转站信誉列表。"""
        if _reputation is None:
            return {"relays": []}
        relays = []
        for r in _reputation.list_all():
            d = r.to_dict()
            # ★ Phase 7：附带评分明细。
            #   延迟突变次数是 _compute_score 的扣分项之一，
            #   但它只存在于评分过程内部、从未出现在响应里 ——
            #   前端无法解释「为什么掉分」，用户只能看到一个黑盒数字。
            d["latency_anomalies"] = _reputation.latency_anomaly_count(r.domain)
            relays.append(d)
        return {
            "relays": relays,
            "summary": _reputation.get_summary(),
        }

    @app.post("/api/relay/precheck")
    async def precheck_relay(payload: Dict[str, Any] = Body(...)):
        """中转站静态风险预检（尚未产生调用记录时使用）。

        用户刚在设置页填入地址、还没发过对话时，信誉库里没有它的记录 ——
        此时若直接查信誉会得到一个现造的空档（score=100），
        等于对用户谎报「信誉良好」。本端点专治这个场景。
        """
        if _reputation is None:
            raise HTTPException(status_code=503, detail="信誉引擎未就绪")
        base_url = str(payload.get("base_url") or "").strip()
        if not base_url:
            raise HTTPException(status_code=400, detail="base_url 不能为空")
        return _reputation.inspect_url(base_url)

    @app.get("/api/config")
    async def get_config():
        """读取配置（API Key 掩码）。"""
        if _config is None:
            raise HTTPException(status_code=503, detail="配置未就绪")
        return _config.to_safe_dict()

    @app.put("/api/config")
    async def update_config(payload: Dict[str, Any] = Body(...)):
        """更新配置。"""
        if _config is None:
            raise HTTPException(status_code=503, detail="配置未就绪")

        if "relay" in payload:
            for k, v in payload["relay"].items():
                if hasattr(_config.relay, k) and v is not None:
                    # 空字符串表示"保持原密钥不变"
                    if k == "api_key" and v == "":
                        continue
                    setattr(_config.relay, k, v)
        if "guard" in payload:
            for k, v in payload["guard"].items():
                if hasattr(_config.guard, k) and v is not None:
                    setattr(_config.guard, k, v)
        if "server" in payload:
            for k, v in payload["server"].items():
                if hasattr(_config.server, k) and v is not None:
                    setattr(_config.server, k, v)

        errors = _config.validate()
        if errors:
            raise HTTPException(status_code=400, detail={"errors": errors})

        # 应用到运行时组件
        if _sanitizer is not None:
            _sanitizer.set_level(_config.guard.security_level)
            for cat, enabled in _config.guard.enabled_categories.items():
                _sanitizer.set_category_enabled(cat, enabled)
            _sanitizer.add_custom_keywords(_config.guard.custom_keywords)
        if _verifier is not None:
            _verifier.set_level(_config.guard.security_level)
            # ★ P2-15 修复：原实现只同步 security_level，
            #   enable_pattern_check 改配置后不生效（且 UI 无入口，等于隐形死配置）
            _verifier.set_pattern_check(_config.guard.enable_pattern_check)

        _config.save()
        return {"ok": True, "config": _config.to_safe_dict()}

    @app.post("/api/pause")
    async def pause_protection(duration_min: int = Body(30, embed=True)):
        """暂停防护（5/30/永久分钟）。"""
        global _paused_until
        if duration_min <= 0:
            _paused_until = time.time() + 365 * 86400   # 永久
        else:
            _paused_until = time.time() + duration_min * 60
        return {
            "ok": True,
            "paused_minutes": duration_min,
            "resume_at": _paused_until,
        }

    @app.post("/api/resume")
    async def resume_protection():
        """恢复防护。"""
        global _paused_until
        _paused_until = 0.0
        return {"ok": True}

    @app.post("/api/reputation/clear")
    async def clear_reputation():
        """清空信誉数据。"""
        if _reputation is None or _storage is None:
            raise HTTPException(status_code=503, detail="信誉引擎未就绪")
        count = _reputation.clear_all()
        _storage.clear_reputations()
        return {"ok": True, "cleared": count}

    @app.get("/api/diagnostics")
    async def diagnostics():
        """诊断信息（分享诊断报告用，全部脱敏）。"""
        if _storage is None or _verifier is None:
            return {"error": "组件未就绪"}
        return {
            "version": app.version,
            "verifier": _verifier.get_stats(),
            "storage": _storage.get_stats(),
            "reputation": _reputation.get_summary() if _reputation else {},
            # ★ P2-4 修复：诊断报告原先在前端硬编码 127.0.0.1:18765，
            #   用户改过端口后报告会给出错误的排查指引
            "server": (
                {"host": _config.server.host, "port": _config.server.port}
                if _config else {}
            ),
            "relay_configured": bool(_config and _config.relay.base_url),
            "relay_domain": (
                _reputation.extract_domain(_config.relay.base_url)
                if (_config and _config.relay.base_url and _reputation)
                else ""
            ),
        }

    return app


# ══════════════════════════════════════════════════════════════
# 辅助函数
# ══════════════════════════════════════════════════════════════


def _csv_escape(value: str) -> str:
    """CSV 字段转义（RFC 4180）。"""
    s = str(value or "")
    if any(ch in s for ch in (",", '"', "\n", "\r")):
        return '"' + s.replace('"', '""') + '"'
    return s


def _make_preview(text: str, limit: int = 500) -> str:
    """生成内容预览（换行归一 + 截断），供日志详情与搜索使用。"""
    if not text:
        return ""
    normalized = " ".join(text.split())
    return normalized[:limit]


def _extract_content(payload: Any) -> str:
    """从 OpenAI/Anthropic 响应结构中提取文本内容。"""
    if isinstance(payload, str):
        return payload
    if not isinstance(payload, dict):
        return str(payload)

    # OpenAI 格式
    choices = payload.get("choices")
    if isinstance(choices, list) and choices:
        message = choices[0].get("message", {}) if isinstance(choices[0], dict) else {}
        content = message.get("content")
        if isinstance(content, str):
            return content
        # Anthropic 格式
        if isinstance(content, list):
            return "\n".join(
                str(c.get("text", "")) for c in content if isinstance(c, dict)
            )

    # Anthropic 顶层 content
    content = payload.get("content")
    if isinstance(content, list):
        return "\n".join(
            str(c.get("text", "")) for c in content if isinstance(c, dict)
        )

    # 工具调用
    tool_calls = payload.get("tool_calls")
    if isinstance(tool_calls, list):
        import json as _json
        return _json.dumps(tool_calls, ensure_ascii=False)

    return payload.get("raw", "") if isinstance(payload.get("raw"), str) else str(payload)


def _set_content(payload: Any, content: str) -> None:
    """把恢复后的内容写回响应结构。"""
    if not isinstance(payload, dict):
        return
    choices = payload.get("choices")
    if isinstance(choices, list) and choices and isinstance(choices[0], dict):
        message = choices[0].get("message")
        if isinstance(message, dict) and isinstance(message.get("content"), str):
            message["content"] = content
            return
    if isinstance(payload.get("content"), list):
        # Anthropic 格式：只替换第一个 text 块
        for item in payload["content"]:
            if isinstance(item, dict) and "text" in item:
                item["text"] = content
                return


def _extract_sse_frames(sse_text: str) -> Tuple[str, List[Any], str]:
    """从 SSE 累积文本中提取内容、tool_calls 与 model。

    ★ v0.1.0 重写：原实现 `_extract_sse_content` 只取
      `choices[0].delta.content` 拼接，把其余一切丢掉 ——
      连带三个后果：
        ① tool_calls 完全不进入被检测文本，而 Claude Code / Cursor
           全靠 tool call 工作，等于流式路径完全绕过第 ① 类检测；
        ② 结构差分拿不到工具名，"未声明工具"判据在流式下永远失效；
        ③ 拿不到 model，"模型降级"判据同样失效。

    SSE 的 tool_call 是分片增量到达的（先来 id+name，后续帧补 arguments），
    这里按 index 归并，还原成完整调用。

    Returns:
        (拼接后的文本, 归并后的 tool_calls 列表, 响应 model)
    """
    parts: List[str] = []
    # index -> {"id":..., "name":..., "arguments": "..."}
    tool_acc: Dict[int, Dict[str, str]] = {}
    model = ""

    for raw_line in sse_text.split("\n"):
        line = raw_line.strip()
        if not line.startswith("data:"):
            continue
        data = line[5:].strip()
        if data == "[DONE]":
            break
        try:
            obj = json.loads(data)
        except json.JSONDecodeError:
            continue
        if not isinstance(obj, dict):
            continue

        if not model:
            m = obj.get("model")
            if isinstance(m, str):
                model = m

        choices = obj.get("choices")
        if not (isinstance(choices, list) and choices):
            continue
        first = choices[0]
        if not isinstance(first, dict):
            continue

        delta = first.get("delta")
        if not isinstance(delta, dict):
            # Anthropic 流式：content_block_delta / delta.text
            delta = first.get("delta", {}) if isinstance(first.get("delta"), dict) else {}

        content = delta.get("content")
        if isinstance(content, str):
            parts.append(content)
        elif isinstance(content, list):
            for blk in content:
                if isinstance(blk, dict) and isinstance(blk.get("text"), str):
                    parts.append(blk["text"])
        # 某些网关把文本放在 delta.text
        dtxt = delta.get("text")
        if isinstance(dtxt, str):
            parts.append(dtxt)

        # 工具调用增量归并
        for tc in delta.get("tool_calls") or []:
            if not isinstance(tc, dict):
                continue
            idx = tc.get("index")
            if not isinstance(idx, int):
                idx = len(tool_acc)
            slot = tool_acc.setdefault(
                idx, {"id": "", "name": "", "arguments": ""}
            )
            if isinstance(tc.get("id"), str):
                slot["id"] = tc["id"]
            fn = tc.get("function")
            if isinstance(fn, dict):
                if isinstance(fn.get("name"), str) and fn["name"]:
                    slot["name"] = fn["name"]
                if isinstance(fn.get("arguments"), str):
                    slot["arguments"] += fn["arguments"]
            # Anthropic 流式：content_block_start 里的 tool_use
            if tc.get("type") == "tool_use" and isinstance(tc.get("name"), str):
                slot["name"] = tc["name"]

    tool_calls: List[Any] = []
    for idx in sorted(tool_acc):
        slot = tool_acc[idx]
        if not slot["name"] and not slot["arguments"]:
            continue
        try:
            args = json.loads(slot["arguments"]) if slot["arguments"] else {}
        except json.JSONDecodeError:
            args = {"_raw": slot["arguments"]}
        tool_calls.append({
            "id": slot["id"] or f"call_{idx}",
            "type": "function",
            "function": {"name": slot["name"], "arguments": args},
        })

    return "".join(parts), tool_calls, model


def _extract_sse_content(sse_text: str) -> str:
    """从 SSE 累积文本中提取 delta 内容（兼容旧调用点）。"""
    return _extract_sse_frames(sse_text)[0]


def _resolve_action(max_sev: str, verify_result: Any) -> str:
    """按合并后的最高严重度决定整体处置。

    ★ 为什么需要它：verifier.verify() 自己算出的 action 只覆盖它
      自己的发现项。而第三层 restorer 也会产出 severity="high" 的
      placeholder_injection（中转站伪造占位符探测原始值），
      原实现把两边的 findings 合并后，却仍沿用 verify_result.action ——
      于是「high 级发现」既不阻断、又被记成 safe。

    复用 verifier 的级别映射，保证两条路径的处置口径完全一致。
    """
    if max_sev == "low":
        return Action.PASS.value
    if _verifier is not None:
        try:
            return _verifier._threshold_for(max_sev)
        except Exception:  # noqa: BLE001
            pass
    # verifier 不可用时的保守兜底：high 直接阻断
    if max_sev == "high":
        return Action.BLOCK.value
    return Action.ALERT.value


def _verify_restored_text(
    restored: str, session_id: str, verifier
) -> List[Any]:
    """对第三层恢复后的内容做一次快速验证。

    ★ 为什么必须放在模块级：它原先是 create_app() 内的一个 @staticmethod，
      却在同一作用域的嵌套 async 生成器里以 self._verify_restored 调用 ——
      嵌套生成器作用域内不存在 self，必然抛 NameError。
      触发条件恰是「本次请求命中过脱敏」，而流式客户端（Claude Code / Cursor）
      几乎必然命中，等于该路径从未跑通过。
    """
    if verifier is None:
        return []
    try:
        return list(verifier.verify(restored[:4000], session_id, None).findings)
    except Exception:  # noqa: BLE001
        return []


def _sanitize_messages_inplace(
    body: Dict[str, Any], sanitizer
) -> List[Any]:
    """逐条消息独立脱敏，就地写回，并返回全部脱敏记录。

    ★ v0.1.0 重写。旧实现把全部消息拼成一个字符串脱敏后整体写回
      最后一条 user 消息，产生三个实际故障：
        ① system prompt 与历史轮次被静默丢弃 —— 中转站收到的请求
           结构与用户发出的完全不同，而这种结构篡改本该是我们要检测的；
        ② 占位符长度 ≠ 原值长度，用 combined 的偏移量去切已替换的
           文本必然错位，实测把一条 assistant 消息切成两半；
        ③ 同一段内容被重复发送（拼接结果含全部历史 + 本轮）。

    逐条处理后每条的 offsets 都相对自身内容，彻底消除偏移问题。
    """
    messages = body.get("messages")
    if not isinstance(messages, list) or sanitizer is None:
        return []

    all_records: List[Any] = []
    offset_base = 0   # 占位符编号跨消息连续递增

    for m in messages:
        if not isinstance(m, dict):
            continue
        content = m.get("content")
        # Anthropic 形态：content 是 [{type,text},...] 分块
        if isinstance(content, list):
            for block in content:
                if isinstance(block, dict) and isinstance(block.get("text"), str):
                    r = sanitizer.sanitize(block["text"])
                    if r.action == Action.BLOCK.value:
                        raise _BlockRequest(
                            r.blocked_reason or "敏感信息阻断",
                            r.hit_categories,
                        )
                    if r.records:
                        block["text"] = _shift_placeholders(
                            r.sanitized_text, r.records, offset_base
                        )
                        all_records.extend(
                            _renumber(r.records, offset_base)
                        )
                        offset_base += len(r.records)
            continue

        if not isinstance(content, str) or not content:
            continue

        r = sanitizer.sanitize(content)
        if r.action == Action.BLOCK.value:
            raise _BlockRequest(
                r.blocked_reason or "敏感信息阻断", r.hit_categories
            )
        if not r.records:
            continue
        m["content"] = _shift_placeholders(
            r.sanitized_text, r.records, offset_base
        )
        all_records.extend(_renumber(r.records, offset_base))
        offset_base += len(r.records)

    return all_records


def _shift_placeholders(text: str, records: List[Any], base: int) -> str:
    """把本条消息内的占位符编号整体后移 base 位。

    sanitizer 每条消息独立编号从 1 开始，而 restorer 是按会话
    统一映射还原的 —— 编号必须在整个请求内唯一，否则第二条消息的
    ⟦XD_1⟧ 会覆盖第一条的记录。
    """
    if base == 0:
        return text
    out = text
    for rec in records:
        out = out.replace(
            rec.redacted, RedactionRecord.placeholder(rec.index + base)
        )
    return out


def _renumber(records: List[Any], base: int) -> List[Any]:
    """把记录里的 index / redacted 同步后移 base 位。"""
    if base == 0:
        return list(records)
    out = []
    for rec in records:
        rec.index = rec.index + base
        rec.redacted = RedactionRecord.placeholder(rec.index)
        out.append(rec)
    return out


class _BlockRequest(Exception):
    """请求侧命中阻断类敏感信息（内部信号，由调用方转 403）。"""

    def __init__(self, reason: str, categories: Optional[List[str]] = None):
        super().__init__(reason)
        self.reason = reason
        self.categories: List[str] = list(categories or [])


def _apply_sanitized(body: Dict[str, Any], sanitizer) -> None:
    """兼容旧签名：就地脱敏并写回（记录由 _sanitize_messages_inplace 返回）。"""
    _sanitize_messages_inplace(body, sanitizer)


def _max_severity(findings: List[Any]) -> str:
    """返回发现项中的最高严重程度。"""
    if not findings:
        return "low"
    order = {"low": 0, "medium": 1, "high": 2}
    return max(findings, key=lambda f: order.get(f.severity, 0)).severity


def _record_log(
    log_type, domain, action, severity, model,
    findings, payload, session_id, redaction_records,
    text_preview: str = "",
) -> None:
    """记录一条日志 + 脱敏记录 + 每日统计。

    Args:
        text_preview: 内容预览（★ 必须由调用方传入，P1-7 修复：
            该字段原先从未赋值，导致日志详情「原始响应片段」永不显示、
            搜索功能的一半条件永久失效）
    """
    if _storage is None:
        return
    try:
        summary = findings[0].detail if findings else "正常转发"
        if len(findings) > 1:
            summary += f"（共 {len(findings)} 项）"
        entry = LogEntry(
            log_type=log_type,
            relay_domain=domain,
            action=action,
            severity=severity,
            model=model,
            finding_count=len(findings),
            summary=summary[:200],
            detail_json=json.dumps(
                [f.to_dict() for f in findings], ensure_ascii=False
            ),
            text_preview=_make_preview(text_preview),
        )
        log_id = _storage.insert_log(entry)
        if redaction_records:
            _storage.insert_redactions(log_id, session_id, redaction_records)

        # 每日统计
        danger = 1 if action == Action.BLOCK.value else 0
        suspect = 1 if action == Action.ALERT.value else 0
        safe = 1 if action == Action.PASS.value else 0
        _storage.update_daily_stats(
            total_calls=1, danger=danger, suspect=suspect, safe=safe,
            redactions=len(redaction_records),
        )
    except Exception as e:  # noqa: BLE001 — 日志失败不应阻断业务
        logger.warning("日志记录失败: %s", e)


def _record_reputation(domain: str, action: str, latency_ms: float, content: str) -> None:
    """更新中转站信誉。"""
    if _reputation is None or not domain or _config is None:
        return
    try:
        rep = _reputation.record_call(
            _config.relay.base_url, action, latency_ms, content
        )
        if _storage is not None:
            _storage.upsert_reputation(rep)
    except Exception as e:  # noqa: BLE001
        logger.warning("信誉记录失败: %s", e)


def _proxy_error(domain, model, session_id, message, t0, log_type):
    """代理层错误响应。"""
    if _storage is not None:
        entry = LogEntry(
            log_type=log_type,
            relay_domain=domain,
            action=Action.BLOCK.value,
            # ★ P2-18 修复：原硬编码 "medium"。中转站超时/不可达属于
            #   链路级失败，不应与「响应内容高危」同级，否则首页
            #   「危险」KPI 会被基础设施抖动刷高，稀释真实告警。
            #   这里区分：代理自身错误 = low（本地链路），内容阻断 = high。
            severity="low",
            model=model,
            summary=message,
        )
        _storage.insert_log(entry)
    return JSONResponse(
        status_code=502,
        content={"error": {"type": "proxy_error", "message": message}},
    )


# ══════════════════════════════════════════════════════════════
# 启动入口
# ══════════════════════════════════════════════════════════════


def run(host: Optional[str] = None, port: Optional[int] = None) -> None:
    """启动个人版代理。

    ★ P2-12 修复：原实现从不读取 sys.argv，README 给出的
      `python -m daoti_xuandun_personal.proxy.app --port 18765`
      中的 --port 被完全丢弃（Tauri 后端正是这样拉起引擎的）。
      现补 argparse 支持。
    """
    import argparse
    import uvicorn

    config = PersonalConfig.load()
    config.apply_env_overrides()

    parser = argparse.ArgumentParser(
        prog="daoti_xuandun_personal.proxy.app",
        description="道体·玄盾 个人版 — 本地代理",
    )
    parser.add_argument("--host", default=None, help="监听地址（仅允许本地）")
    parser.add_argument("--port", type=int, default=None, help="监听端口（默认 18765）")
    parser.add_argument(
        "--log-level", default=None,
        choices=["critical", "error", "warning", "info", "debug"],
        help="日志级别",
    )
    args = parser.parse_args()

    actual_host = args.host or host or config.server.host
    actual_port = args.port or port or config.server.port
    if args.log_level:
        config.server.log_level = args.log_level

    # 再次校验（Tauri 传入的 host 同样受安全底线约束）
    config.server.host = actual_host
    config.server.port = actual_port
    errors = config.server.validate()
    if errors:
        print("配置错误：")
        for e in errors:
            print(f"  - {e}")
        raise SystemExit(1)

    logging.basicConfig(
        level=getattr(logging, config.server.log_level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    print("=" * 64)
    print("  道体·玄盾 个人版 — 本地代理")
    print("=" * 64)
    print(f"  监听地址:  http://{actual_host}:{actual_port}")
    print(f"  中转站:    {config.relay.base_url or '(未配置，请先在设置中填写)'}")
    print(f"  安全级别:  {config.guard.security_level}")
    print()
    print("  将 AI 工具的 API 地址设置为：")
    print(f"    http://{actual_host}:{actual_port}/v1")
    print("=" * 64)

    uvicorn.run(create_app(), host=actual_host, port=actual_port, log_level="info")


if __name__ == "__main__":
    run()
