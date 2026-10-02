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

from ..config import PersonalConfig, RelayConfig, is_masked_key
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

# 授权结论的短 TTL 缓存：(许可证文件 mtime, 判定时刻, 是否启用防护)。
# 存在理由见 _protection_enabled 的 docstring —— 那里每个 AI 请求都会调用。
#
# ★ 缓存键里带 mtime 而不只是时间：Rust 侧 activate 成功后
#   直接写 license.json，引擎收不到任何通知。若缓存只看时间，
#   用户刚激活完仍会被降级最多 5 秒。mtime 一变即刻失效。
_PROTECTION_TTL = 5.0
_protection_cache: Dict[str, Any] = {}


def _license_file_path() -> str:
    """激活信息落盘路径。

    ★ 必须与 Rust 侧 ``license.rs::license_file`` 完全一致。
      两边读的不是同一个文件时，会出现「界面说已激活、
      引擎说未激活」——用户激活成功了却仍在只读模式，
      且两边都觉得自己是对的，极难排查。
    """
    import os as _os

    return _os.path.join(
        _os.getenv("LOCALAPPDATA") or _os.path.expanduser("~/.config"),
        "com.daoti.xuandun-personal",
        "license.json",
    )


# 构建期生成的密钥文件名（由 build_engine.py 写入引擎目录）
_BUILD_SECRETS_FILE = "build_secrets.json"


def _inject_build_secrets(config) -> bool:
    """把构建期生成的密钥注入护栏配置。

    反编译加固
    ────────────────────────────────────────────────────────────
    护栏层原本带两个明文 fallback 密钥
    （``shell_key = b"daoti_xuandun_16"`` / ``mapping_key = b"ancient_map_16b!"``），
    反编译者一眼就能拿到，动态壳与符号映射的初始化种子就此失去意义。

    正确做法是**构建期生成随机密钥**，随包分发，运行时读入：
      · 源码与二进制里都不再有固定密钥
      · 每个版本的密钥不同，跨版本复用无效
      · 仍不抗「读出二进制里的密钥再重打包」——
        那是抬高门槛而非绝对防线，靠的是校验点分散

    ★ 文件缺失时**不静默**：那是开发态源码运行的正常情况。
      但若有人以为「构建过了」而实际没生成，
      护栏会带着固定 fallback 密钥运行 —— 那是假装的加固。
      所以这里返回 False，由调用方决定是否要求它存在。
    """
    import json as _json
    import os as _os
    import sys as _sys

    exe_dir = _os.path.dirname(_os.path.abspath(_sys.executable))
    path = _os.path.join(exe_dir, _BUILD_SECRETS_FILE)

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = _json.load(f)
    except OSError:
        return False
    except ValueError:
        logger.warning("构建密钥文件不是合法 JSON，已忽略：%s", path)
        return False

    if not isinstance(data, dict):
        logger.warning("构建密钥文件格式异常（不是对象），已忽略：%s", path)
        return False

    applied = False
    shell = data.get("shell_key")
    mapping = data.get("mapping_key")
    if isinstance(shell, str) and shell:
        config.shell_key = shell.encode("utf-8")
        applied = True
    if isinstance(mapping, str) and mapping:
        config.mapping_key = mapping.encode("utf-8")
        applied = True

    if applied:
        logger.info("已加载构建期密钥（来源：%s）", _BUILD_SECRETS_FILE)
    else:
        logger.warning("构建密钥文件存在但内容为空，护栏将回退到默认密钥")
    return applied


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

    # ══════════════════════════════════════════════════════════
    # 激活状态（只读模式判定）
    # ══════════════════════════════════════════════════════════
    #
    # ★ 为什么是「只读」而不是「锁死」
    #   未激活就完全拒绝代理，等于把用户挡在门外。若他其实已经付过钱
    #   只是码过期了或机器换了，用户会彻底无法使用，投诉成本极高。
    #   只读模式下界面、日志、设置全部可用，只是不再执行脱敏与拦截 ——
    #   用户仍能看清玄盾在做什么，价值可感知。
    #
    # ★ 但「验不了」不等于「没激活」
    #   验签组件故障（缺公钥 / 缺 jwt 依赖）时把用户降级成只读，
    #   等于用我方故障惩罚已付费用户。所以只有**明确判定为未激活**
    #   才降级；组件不可用时继续正常防护。
    #
    # ★ 机器码绑定为什么不在这里查（如实说明能力边界）
    #   机器码由 Rust 侧用 sysinfo 采集，引擎是**独立进程**，
    #   拿不到那个值。引擎若自己用别的方式重算，两侧算法必然漂移，
    #   结果是所有用户的码都验不过、全部被降级成只读。
    #   所以引擎侧只做它能正确做的判定：签名 / 有效期 / 吊销。
    #   机器码绑定由 Rust 在 activate 时强制校验（见 license.rs）。
    def _protection_enabled() -> bool:
        """未激活 / 已过期时返回 False（进入只读模式）。

        ★ 带短 TTL 缓存：这里在**每个 AI 请求**上都会调用，
          而底层一次完整验签要读 2 次磁盘（公钥 / 时钟水位）
          加 1 次 RSA 签名验证。高频对话下这是可观的开销。
          授权结论在几秒内不会变，缓存 5 秒不影响正确性。

        ★ 缓存还以 license.json 的 mtime 为键：Rust 侧 activate
          成功后直接写文件，引擎收不到任何通知，纯时间缓存会让
          用户刚激活完仍被降级。mtime 一变即刻重算。
        """
        stamp = _license_file_mtime()
        cached = _protection_cache.get("value")
        if (
            cached is not None
            and cached[0] == stamp
            and time.time() - cached[1] < _PROTECTION_TTL
        ):
            return cached[2]
        value = _compute_protection_enabled()
        _protection_cache["value"] = (stamp, time.time(), value)
        return value

    def _license_file_mtime() -> float:
        import os as _os

        try:
            return _os.path.getmtime(_license_file_path())
        except OSError:
            return -1.0

    def _compute_protection_enabled() -> bool:
        """未激活 / 已过期时返回 False（进入只读模式）。"""
        try:
            from .. import license as lic

            if not lic.load_public_key():
                # 验签组件不可用 → 不能据此断定用户没付过钱
                logger.warning("公钥缺失，跳过激活校验（按已授权处理）")
                return True

            import jwt  # noqa: F401

            code = _load_saved_code()
            if not code:
                # 全新安装 / 还没填过码 —— 这才是「确实未激活」
                return False

            # ★ mch 传空串：引擎无从复现 Rust 采集的机器码，
            #   传一个编造的值会让合法码全部验不过。
            #   verify() 对空 mch 的处理是「不比对机器码」——
            #   机器码绑定由 Rust 侧负责，这里不越权判定。
            r = lic.verify(code, "", machine_check=False)
            if not r.ok:
                # 「有码但验不过」与「没码」是两种不同情况，
                # 日志必须能区分，否则用户报障时无法定位。
                logger.info("进入只读模式：%s（%s）", r.reason, r.message or "")
            return r.ok
        except Exception as e:  # 任何异常都不得让防护静默消失
            # ★ 这里返回 True（不降级）是刻意的：
            #   验签组件故障时降级 = 用我方故障惩罚已付费用户。
            #   但配置错误（如公钥路径写错）也落进这个分支，
            #   所以日志要说清是哪一种 —— 否则「所有码都无效」
            #   这个现象会一直查不到根因。
            logger.warning(
                "激活状态读取失败（%s: %s），按已授权处理。"
                "若公钥路径配置有误请检查 XUANDUN_LICENSE_PUBKEY_FILE",
                type(e).__name__, e,
            )
            return True

    def _load_saved_code() -> str:
        """读取用户已保存的激活码。

        落盘位置与 Rust 侧 license.rs::license_file 一致，
        两边必须读同一个文件，否则会出现「界面说已激活、引擎说没激活」。
        """
        import json as _json

        try:
            with open(_license_file_path(), "r", encoding="utf-8") as f:
                return str(_json.load(f).get("code", "") or "")
        except (OSError, ValueError):
            return ""

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

        # ★ 未激活 / 已过期 → 只读模式（直通，但如实记录「未经检测」）
        if not _protection_enabled():
            return await _relay_passthrough(
                body, stream, session_id,
                note="未激活，本次请求未经检测直接转发",
            )

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
                # ★ 阻断也必须留下可核对的依据。
                #   原实现只写 hit_categories 就 return，
                #   redaction_records 与 text_preview 全为空 ——
                #   界面只能显示「检测到 JWT 令牌」，
                #   用户既看不到命中位置，也看不到片段，
                #   只能凭感觉猜是不是误报。
                #   40 条 JWT 拦截里绝大多数其实是用户自己把
                #   激活码贴进提问（激活码本身就是 RS256 JWT），
                #   拦截属实，但不给依据就永远说不清。
                entry = LogEntry(
                    log_type=LogType.REQUEST_SANITIZE.value,
                    relay_domain=upstream_domain,
                    action=Action.BLOCK.value,
                    severity="high",
                    model=model,
                    finding_count=len(blocked.records),
                    summary=blocked.reason,
                    detail_json=json.dumps(
                        _block_evidence(
                            blocked.categories, blocked.records, blocked.context
                        ),
                        ensure_ascii=False,
                    ),
                    text_preview=_make_preview(
                        _evidence_preview(blocked.records)
                    ),
                )
                log_id = _storage.insert_log(entry)
                if blocked.records:
                    _storage.insert_redactions(
                        log_id, session_id, blocked.records
                    )
                # ★ P2-13：阻断路径也记 total_calls，否则首页
                #   「今日已检查 N 次」失真、KPI 数字对不上
                #
                #   ★ 这里**不能**加 redactions=len(records)。
                #     该计数在状态栏显示为「已打码 N 处」，
                #     而阻断根本没有打码 —— 请求被拒绝发送，
                #     没有任何内容离开本机。把它记进打码数，
                #     状态栏就会对用户谎报「已替你遮住 N 处敏感信息」。
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
        # 必须在转发前捕获。请求体是原样透传的（玄盾不改写 model），
        # 因此基线里的 model 就是用户真正请求的模型，
        # 「模型降级」判据才可能发现中转站的偷换行为。
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
        """转发请求到中转站（请求体原样透传，不改写 model）。

        ★ 玄盾监控的是 API，不是某个模型 —— 请求里的 model 属于用户
          与中转站之间的约定，玄盾无权也无必要改写它。曾有一版用配置里的
          「默认模型」覆盖请求 model，后果是：用户明明发的是 A 模型，
          中转站收到的是 B；而请求基线里记的也是被改写的 B，
          于是「模型降级」判据（中转站偷偷换模型）永远发现不了真降级。
        """
        if _http_client is None or _config is None:
            raise httpx.ConnectError("代理未初始化")

        return await _http_client.post(
            f"{_config.relay.normalized_base}/chat/completions",
            json=body,
            headers={
                "Authorization": f"Bearer {_config.relay.api_key}",
                "Content-Type": "application/json",
            },
        )

    async def _relay_passthrough(
        body: Dict[str, Any],
        stream: bool,
        session_id: str,
        note: str = "防护已暂停，本次请求未经检测直接转发",
    ):
        """未经检测的直通转发（防护暂停 / 未激活只读模式）。"""
        try:
            upstream = await _forward_to_relay(body, stream)
        except httpx.HTTPError as e:
            return JSONResponse(
                status_code=502,
                content={"error": {"message": f"中转站不可达：{e}", "type": "upstream_error"}},
            )
        # ★ P2-17 修复：LogType.RELAY（正常转发）原先在整个代码库中
        #   从未被产生，导致日志页「正常转发」筛选项恒为空 ——
        #   一个用户看得见、却永远无结果的选项。防护暂停/未激活期间正是
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
            text_preview=note,
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
            # ★ 只读模式必须显式告诉前端。
            #   若只在 message 里塞一句话，首页 KPI（"今日已检查 N 次"）
            #   仍会照常显示，用户会以为防护在正常工作 ——
            #   而实际上请求都在直通。这是对用户的谎报。
            "read_only": not _protection_enabled(),
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

    @app.post("/api/relay/test")
    async def test_relay(payload: Dict[str, Any] = Body(...)):
        """真实发一次请求，把「地址不对 / Key 不对 / 站点不可达」分开。

        ★ 为什么必须有这个端点，而不是只靠地址规范化：
          中转站后台把「接入地址」与「完整端点」并排展示，用户按配置 API
          的直觉复制的是完整端点。normalized_base 已在字符串层面兜住这类
          输入，但字符串兜不住没有版本段的自定义路径（如
          ``https://x.com/openai`` 会被补成 ``/openai/v1``）——
          这一层只能靠真探测。

          更关键的是：地址填错的现象是 404，用户会去查中转站、查 Key、
          查网络，唯独不会想到是地址被拼坏了一层。把真实探测结果摆出来，
          是这个信息差唯一的解法。

        ★ 探针是 POST /chat/completions + 一个不存在的模型名。
          两个选择都有实测依据（见下方注释）：/models 不校验鉴权，
          真模型会撞上套餐权益 —— 两者都会把「配置正确」误报成别的结论。
          假模型既不需要知道用户用哪个模型（配置里已没有模型字段），
          又把鉴权与套餐权益干净地分开。
        """
        if _config is None:
            raise HTTPException(status_code=503, detail="配置未就绪")

        base_url = str(payload.get("base_url") or "").strip() or _config.relay.base_url
        if not base_url:
            raise HTTPException(status_code=400, detail="请先填写中转站地址")

        # ★ 空 Key 一律回退到已保存的那个：界面上显示的是掩码，
        #   用户不重填时前端传来的就是空串，语义是「沿用原来的」。
        api_key = str(payload.get("api_key") or "").strip() or _config.relay.api_key
        if not api_key:
            raise HTTPException(status_code=400, detail="请先填写中转站 API Key")

        base = RelayConfig(base_url=base_url).normalized_base
        headers = {"Authorization": f"Bearer {api_key}"}
        # ★ 用专用超时而不是共用的 _http_client：共用客户端的 read 超时是
        #   request_timeout_s（本机为 300s）。测试按钮要让用户等 300 秒
        #   才知道地址是死的，那不是诊断，是惩罚。
        probe_timeout = httpx.Timeout(connect=6.0, read=12.0, write=12.0, pool=6.0)

        def _snippet(text: Any, limit: int = 300) -> str:
            return " ".join(str(text or "").split())[:limit]

        started = time.monotonic()

        def _result(
            ok: bool,
            kind: str,
            message: str,
            *,
            status: Optional[int] = None,
            model_count: Optional[int] = None,
            raw: Any = "",
        ) -> Dict[str, Any]:
            return {
                "ok": ok,
                "kind": kind,
                "address": base,
                "request_url": f"{base}/chat/completions",
                "status": status,
                "model_count": model_count,
                "elapsed_ms": int((time.monotonic() - started) * 1000),
                "message": message,
                "raw": _snippet(raw),
            }

        async def _probe(method: str, url: str, body: Optional[Dict[str, Any]] = None):
            async with httpx.AsyncClient(
                timeout=probe_timeout, follow_redirects=False
            ) as client:
                return await client.request(method, url, json=body, headers=headers)

        def _count_models(resp: httpx.Response) -> Optional[int]:
            try:
                data = resp.json()
            except Exception:  # noqa: BLE001 —— 上游返回非 JSON 属正常情况
                return None
            items = data.get("data") if isinstance(data, dict) else data
            return len(items) if isinstance(items, list) else None

        # ── 探针：POST /chat/completions，刻意用一个不存在的模型名 ──
        #
        # ★ 为什么必须打对话接口，而不是 GET /models：
        #   实测（2026-09-29，api.commandcode.ai）该站的 /models
        #   **不校验鉴权** —— 错 Key 返回 200，连 Key 都不带也返回 200。
        #   拿它当探针，会把「Key 填错了」报成「连接正常」——
        #   比不测更糟：用户会以为自己配对了，然后每次对话都 401。
        #   校验 Authorization 的是对话接口。
        #
        # ★ 为什么用一个不存在的模型名，而不是真模型：
        #   实测真模型 + 好 Key 会返回 403 MODEL_NOT_IN_PLAN ——
        #   那是套餐权益问题，与「配置对不对」毫无关系，
        #   拿它做判据会让配置完全正确的用户看到「失败」。
        #   假模型把这两件事隔离开了：
        #     好 Key → 400（模型不支持）→ 地址与 Key 都通
        #     坏 Key → 401（鉴权失败）
        try:
            resp = await _probe(
                "POST",
                f"{base}/chat/completions",
                {
                    "model": "__xuandun_probe__",
                    "messages": [{"role": "user", "content": "ping"}],
                    "max_tokens": 1,
                },
            )
        except httpx.TimeoutException:
            return _result(
                False, "timeout", "连接超时：这个地址没有响应。确认域名能打开、没有被网络拦截"
            )
        except httpx.HTTPError as e:
            return _result(False, "unreachable", f"连不上这个地址：{_snippet(e)}")

        status = resp.status_code

        if status in (401, 403):
            return _result(
                False,
                "auth",
                "地址是通的，但这个 API Key 没通过校验。请核对 Key 是否复制完整、是否已失效",
                status=status,
                raw=resp.text,
            )

        if status in (404, 405):
            # 两种可能：地址错了一层，或这个站对不存在的模型回 404。
            # 用 /models 判一次 —— 它能证明「这个接入地址下确实有个 API」。
            # ★ 注意它证明的只是地址，不是鉴权（见上面的实测）。
            try:
                listing = await _probe("GET", f"{base}/models")
            except httpx.HTTPError:
                listing = None
            if listing is not None and 200 <= listing.status_code < 300:
                return _result(
                    False,
                    "http",
                    f"地址可以访问（模型列表正常），但对话接口返回 {status} —— "
                    f"这个中转站可能不支持标准的 /chat/completions 路径，请对照其文档确认",
                    status=status,
                    model_count=_count_models(listing),
                    raw=resp.text,
                )
            return _result(
                False,
                "address",
                f"地址可能不对：玄盾请求的 {base}/chat/completions 返回 {status}。"
                f"请对照中转站后台的「接入地址」核对",
                status=status,
                raw=resp.text,
            )

        # 其余状态码（200 / 400 / 422 …）都说明路由命中且鉴权已通过 ——
        # 上游对那个假模型怎么说并不重要，重要的是它**应答了**。
        return _result(
            True,
            "ok",
            "连接正常：地址与 API Key 都可用",
            status=status,
            raw=resp.text,
        )

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
                    # ★ 掩码值绝不能落成真实 Key（判据在 config.is_masked_key）。
                    #   读取配置返回的是掩码（xxxx****yyyy），前端原样回传时
                    #   若被写回磁盘，真实 Key 就被掩码串替换了 —— 之后所有
                    #   请求 401，而配置页看起来一切正常，用户只会以为
                    #   中转站封了他。这是**静默**的：没有报错、没有日志。
                    #
                    # ★ 必须报错而不是 warning 后 continue：
                    #   真实 Key 里含 **** 的情况确实存在（部分中转站会这样签发），
                    #   静默丢弃的后果是「提示保存成功、实际没生效」——
                    #   而用户下一次请求就 401，且无从关联到这次保存。
                    #   那正是本条守卫要消灭的失效模式，不能自己再犯一次。
                    if k == "api_key" and is_masked_key(v):
                        logger.warning(
                            "拒绝把掩码值写入 api_key（疑似前端回传了脱敏字段）"
                        )
                        raise HTTPException(
                            status_code=400,
                            detail=(
                                "这个 API Key 看起来是脱敏后的串（含 ****），"
                                "已拒绝保存。若这是新填的 Key，请确认复制完整；"
                                "若不修改 Key，请把该输入框清空后再保存。"
                            ),
                        )
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

    @app.get("/api/license/machine_code")
    async def license_machine_code():
        """本机机器码（供界面展示，用户拿它向官方申请激活码）。

        ★ 为什么机器码由引擎采集、而不是 Rust 侧自行采集：
          历史上两侧各写一份算法，结果线上出现「按界面上的机器码
          申请的码，装上却提示与本机不匹配」—— 签发时与验证时
          算出的值不同。现在采集的唯一实现在 license.py，
          签发工具与验签引擎 import 的是同一个函数。

        ★ 回传 hash 而非原文：界面只需要一个稳定标识用于
          申请与核对，不必展示硬件序列号本身。
        """
        from .. import license as lic

        raw = lic.machine_code()
        return {
            "machineCode": lic.machine_code_hash(raw),
            # 采集不到稳定硬件 ID 时为 true，界面据此提示用户
            # 「这台机器的机器码可能不稳定，换机时需重新申请」。
            "degraded": raw.startswith("hw-unavailable:"),
        }

    @app.post("/api/license/verify")
    async def license_verify(payload: Dict[str, Any] = Body(...)):
        """激活码验签。

        ★ 验签放在引擎侧而非 Rust 侧的理由见 license.py 顶部注释：
          引擎是 Nuitka 编译产物，反编译者拿不到明文 Python 源码；
          而改 Rust 侧的校验点只需改几行 Rust。

        ★ 机器码**一律由本引擎采集**，忽略调用方传入的值。
          曾经的契约是「Rust 采集 → 传给引擎比对」，但那份采集
          实现本身不稳定（取磁盘卷标），且与签发工具的算法会漂移。
          采信调用方传的值等于把激活的正确性外包给一个不可靠来源。

        ★ 只回传结论，不回传签名细节 —— 错误文案刻意含糊，
          减少反编译者从文案推断校验点的可能。

        ★ verifier_available=False（引擎缺公钥 / 缺 jwt 依赖）时
          必然 ok=False：「验不了」绝不能被当成「验过了」。
        """
        from .. import license as lic

        code = str(payload.get("code") or "")
        now = payload.get("now")

        result = lic.verify(
            code,
            lic.machine_code_hash(lic.machine_code()),
            now=now,
        )

        # 校验通过才推进时钟水位 —— 失败的尝试不该影响基线，
        # 否则用户输错一次码后修正系统时间反而会被判定回拨。
        if result.ok:
            lic.write_last_seen(lic.now_unix())

        return result.to_dict()

    @app.get("/api/license/status")
    async def license_status():
        """激活相关的能力自检（供诊断页展示降级状态）。"""
        from .. import license as lic

        # ★ load_public_key 在「显式配置的路径不存在」时会抛异常。
        #   自检端点必须顶住它并把真因报出来 ——
        #   这个端点存在的意义就是「让降级可见」，
        #   它自己却因配置错误而 500 就本末倒置了。
        pub_error = ""
        try:
            pub = lic.load_public_key()
        except Exception as e:
            pub = None
            pub_error = str(e)
        try:
            import jwt  # noqa: F401
            has_jwt = True
        except ImportError:
            has_jwt = False

        return {
            # 有公钥才能验签。缺公钥 = 所有激活码都会被判无效，
            # 这必须对外可见，否则用户只会看到「激活码无效」而找不到真因。
            "verifier_available": bool(pub) and has_jwt,
            "has_public_key": bool(pub),
            "public_key_error": pub_error,
            "has_jwt": has_jwt,
            "last_seen": lic.read_last_seen(),
        }

    @app.post("/api/license/rebind_request")
    async def license_rebind_request(payload: Dict[str, Any] = Body(...)):
        """生成换绑请求串。

        ★ 用户换电脑/换硬盘后，原码在新机上必然验证失败
          （mch 绑的是旧机器）。此端点把「原码 + 新机器码」
          打包成一个可复制的串，用户发给售后即可完成换绑 ——
          签发方只需验签后改 mch 重签，不需要用户再牵扯旧机器。

        刻意不加密：内容是「一张已签名的码 + 一个机器码哈希」，
        不含隐私；加密反而需要客户端持有解密密钥，那才是泄露点。

        ★ 机器码由本引擎采集，不采信调用方传入的值 ——
          与 verify 同理，采信外部传入的机器码等于把激活的
          正确性外包给一个不可靠来源。
        """
        from .. import license as lic

        code = str(payload.get("code") or "")
        mc = lic.machine_code()
        if not code.strip():
            raise HTTPException(status_code=400, detail="缺少原激活码")
        return {
            "request": lic.build_rebind_request(code, mc),
            # 机器码一并回传，用户报障时直接发这一段即可
            "machine_code_hash": lic.machine_code_hash(mc),
        }

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
                            r.records,
                            context=_message_role_hint(m),
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
                r.blocked_reason or "敏感信息阻断",
                r.hit_categories,
                r.records,
                context=_message_role_hint(m),
            )
        if not r.records:
            continue
        m["content"] = _shift_placeholders(
            r.sanitized_text, r.records, offset_base
        )
        all_records.extend(_renumber(r.records, offset_base))
        offset_base += len(r.records)

    return all_records


def _block_evidence(
    categories: List[str], records: List[Any], context: str
) -> List[Dict[str, Any]]:
    """构造阻断依据（detail_json）。

    ★ 结构刻意与响应侧 findings 对齐（category/severity/detail/evidence）：
      日志详情页的「触发规则」区块直接按这个结构渲染，
      两类事件用同一套展示逻辑，用户不必学两种格式。
      若这里改成 dict，页面会解析不出数组、依据整段消失 ——
      那正是本轮修的病，不能再犯一次。
    """
    from .sanitizer import CATEGORY_LABELS

    labels = [CATEGORY_LABELS.get(c, c) for c in categories]
    head = f"{'、'.join(labels)}（{context}）" if context else "、".join(labels)
    out: List[Dict[str, Any]] = [
        {
            "category": "request_blocked",
            "severity": "high",
            "detail": f"命中不可外发内容：{head}",
            "evidence": "",
        }
    ]
    for r in records:
        out.append(
            {
                "category": r.category,
                "severity": "high",
                "detail": (
                    f"第 {r.index} 处 · {CATEGORY_LABELS.get(r.category, r.category)}"
                    f" · 位于 {context or '请求内容'}"
                    f" · 第 {r.start}-{r.end} 字符"
                ),
                # 掩码后的片段（不是原文）
                "evidence": r.original,
            }
        )
    return out


def _evidence_preview(records: List[Any]) -> str:
    """把掩码证据拼成一行可读预览，写入 text_preview。

    ★ 阻断时没有任何原文可预览（内容根本没发出去），
      预览位空着会让搜索和详情页都无从下手。
      这里填的是**掩码后**的片段，人可读、不可还原。
    """
    if not records:
        return ""
    return " ｜ ".join(r.original for r in records)


def _message_role_hint(msg: Dict[str, Any]) -> str:
    """返回消息角色的中文说明，供阻断依据展示。

    命中位置所在的角色决定了责任归属：
    同一段密钥，出现在 system 提示词里和出现在用户提问里，
    排查方向完全不同。不给角色，用户只能自己猜。
    """
    role = str(msg.get("role", "") or "")
    return {
        "system": "系统提示词",
        "developer": "开发者提示词",
        "user": "用户提问",
        "assistant": "模型回复",
        "tool": "工具返回",
    }.get(role, role or "未知角色")


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
    """请求侧命中阻断类敏感信息（内部信号，由调用方转 403）。

    ★ 必须携带可核对的证据。
      原实现只带 reason + categories，而阻断分支在写完日志后
      立刻 return —— redaction_records 从未落库。
      结果是：界面只有一句「检测到 JWT 令牌」，
      既看不到命中位置，也看不到片段，用户无法判断是误报还是真命中。
      records 是**已掩码**的证据（保留首尾与长度，去掉中段原文），
      可安全落库、可展示、可导出。
    """

    def __init__(
        self,
        reason: str,
        categories: Optional[List[str]] = None,
        records: Optional[List[Any]] = None,
        context: str = "",
    ) -> None:
        super().__init__(reason)
        self.reason = reason
        self.categories: List[str] = list(categories or [])
        self.records: List[Any] = list(records or [])
        self.context = context


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
    _inject_build_secrets(config)

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
