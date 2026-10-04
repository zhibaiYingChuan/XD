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

from .. import paths
from ..config import (
    PersonalConfig,
    is_masked_key,
    mask_relay_key,
    normalize_relay_base,
)
from ..reputation.tracker import ReputationTracker
from ..storage.db import PersonalStorage
from ..types import Action, LogEntry, LogType, RedactionRecord, SecurityLevel
from .baseline import build_baseline
from .restorer import ContentRestorer
from .sanitizer import RequestSanitizer
from .verifier import OBSERVATION_ONLY_SIGNALS, ResponseVerifier

logger = logging.getLogger("xuandun-personal.app")

# 流式响应中期验证阈值（字节）
STREAM_VERIFY_THRESHOLD = 8192

# 统计类信号（见 verifier.PatternTracker._STATISTICAL）。
# 这里用于「给用户报哪一条」时跳过它们 ——
# 「本次长度偏离 124σ」对用户毫无意义，说了只会让他更困惑。
_STATISTICAL_SIGNALS = frozenset({"length_anomaly", "structure_anomaly"})

# 全局单例（lifespan 初始化）
_config: Optional[PersonalConfig] = None
_storage: Optional[PersonalStorage] = None
_sanitizer: Optional[RequestSanitizer] = None
_verifier: Optional[ResponseVerifier] = None
_restorer: Optional[ContentRestorer] = None
_reputation: Optional[ReputationTracker] = None
_http_client: Optional[httpx.AsyncClient] = None
_paused_until: float = 0.0     # 暂停截止时间戳

# ★ run() 解析出的**实际**监听端口（含 --port / 环境变量覆盖）。
#   lifespan 里的 _config 是独立 load() 的对象，带的是配置文件里的端口，
#   与实际监听值可能不同 —— 日志必须用这个，否则会报出错的端口。
_actual_port: Optional[int] = None

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
    ★ 目录走 paths.data_dir()：开发/测试隔离时两侧一起挪走。
    """
    return str(paths.data_file("license.json"))


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
    #
    # ★ v0.1.0：导入时会把分数**按当前算法重算**（见
    #   tracker.import_reputation）。重算结果必须立刻写回库，
    #   否则库里留着的仍是旧算法的错值（比如被扣到 0 的那个）。
    #   内存是对的、库是错的 —— 这种不一致会在下次
    #   「设置页重置信誉」或任何直接读库的地方重新冒出来，
    #   而用户看到的 0 分正来源于此。
    # ★★ 迁移必须在 load_reputations **之前**（2026-10-04）：
    #    否则加载进来的是旧键，而新请求写的是新键 ——
    #    同一家在内存里出现两份，界面上重复显示。
    _migrate_relay_keys_to_fingerprint()

    for rep in _storage.load_reputations():
        _reputation.import_reputation(rep)
        try:
            _storage.upsert_reputation(rep)
        except Exception as e:  # noqa: BLE001
            # 重算后的分数写回失败不应阻断启动：
            # 内存里的值已经是正确的，接口照常可用。
            logger.warning("信誉分数回写失败（内存值仍正确）: %s", e)

    # ③ HTTP 客户端
    timeout_s = _config.server.request_timeout_s
    _http_client = httpx.AsyncClient(
        timeout=httpx.Timeout(
            connect=10.0, read=timeout_s, write=30.0, pool=10.0
        ),
        limits=httpx.Limits(max_connections=50, max_keepalive_connections=20),
        follow_redirects=False,      # ★ 安全：不自动跟随中转站重定向
    )

    # ★ 必须报**实际**监听端口，不能报 _config.server.port。
    #   两者在 --port 传参时不相等：run() 解析出的 actual_port 写进了
    #   run() 里的局部 config，而模块级 _config 是 lifespan 里
    #   独立 load() 出来的另一个对象，仍带着配置文件里的旧端口。
    #   日志于是显示 18765 而实际监听 18766 ——
    #   排查时会被直接带偏：这正是「日志说一套、实际做另一套」。
    logger.info(
        "个人版代理就绪: http://%s:%s → %s（数据目录 %s）",
        _config.server.host, _actual_port or _config.server.port,
        _config.relay.base_url or "(未配置)",
        paths.data_dir(),
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
        version="0.1.5-alpha",
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

        # ★★ v0.1.0：先判定这次该转发给哪家。
        #   必须在任何转发之前完成 —— 之后的日志、信誉、
        #   基线全都依赖「实际发给了谁」，
        #   否则多中转站下这些记录会全部记到当前启用项头上，
        #   而用户实际用的是另一家。
        resolved = _resolve_upstream(request) or {}
        target_relay = resolved.get("relay")
        matched_by = resolved.get("matched_by", "active")
        # ★ 2026-10-04：信誉键改为「主机#Key指纹」。
        #   同一地址配两把 Key（同一家的两个账号）此前会被并成一条
        #   信誉记录 —— 用户看到「一家」的分数，实际混了两家。
        #   日志域名、信誉主键、结果里的「本次发给了谁」共用这一个键，
        #   三条口径才不会分叉。
        upstream_domain = (
            _reputation.reputation_key(
                str(target_relay.get("base_url") or ""),
                str(target_relay.get("api_key") or ""),
            )
            if (_reputation and target_relay) else ""
        )

        # 防护已暂停 → 直通
        if time.time() < _paused_until:
            return await _relay_passthrough(
                body, stream, session_id, target=target_relay,
                matched_by=matched_by,
            )

        # ★ 未激活 / 已过期 → 只读模式（直通，但如实记录「未经检测」）
        if not _protection_enabled():
            return await _relay_passthrough(
                body, stream, session_id,
                note="未激活，本次请求未经检测直接转发",
                target=target_relay, matched_by=matched_by,
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
            upstream_response = await _forward_to_relay(
                body, stream, target_relay)
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

    async def _forward_to_relay(body: Dict[str, Any], stream: bool,
                                target: Optional[Dict[str, Any]] = None):
        """转发请求到中转站（请求体原样透传，不改写 model）。

        ★ 玄盾监控的是 API，不是某个模型 —— 请求里的 model 属于用户
          与中转站之间的约定，玄盾无权也无必要改写它。曾有一版用配置里的
          「默认模型」覆盖请求 model，后果是：用户明明发的是 A 模型，
          中转站收到的是 B；而请求基线里记的也是被改写的 B，
          于是「模型降级」判据（中转站偷偷换模型）永远发现不了真降级。

        ★★ v0.1.0：target 决定转发给哪家、用哪把 Key。
          原实现无条件用配置里的 Key 覆盖 Authorization，
          多中转站下会让用户「以为在用 A、实际扣 B 的钱」。
          target 为 None 时回落到当前启用项（兼容单条配置）。
        """
        if _http_client is None or _config is None:
            raise httpx.ConnectError("代理未初始化")

        target = resolve_forward_target(target)
        base = target["base"]
        api_key = target["api_key"]

        return await _http_client.post(
            f"{base}/chat/completions",
            json=body,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
        )

    async def _relay_passthrough(
        body: Dict[str, Any],
        stream: bool,
        session_id: str,
        note: str = "防护已暂停，本次请求未经检测直接转发",
        target: Optional[Dict[str, Any]] = None,
        matched_by: str = "active",
    ):
        """未经检测的直通转发（防护暂停 / 未激活只读模式）。

        ★ v0.1.0：日志里必须记**实际转发给的那家**。
          原实现记的是配置里的当前启用项，
          多中转站下会把「用户用的是 A」记成 B，
          信誉与日志全记错对象。
        """
        if target is None and _config is not None:
            target = _config.relay.all_relays()[0]
        try:
            upstream = await _forward_to_relay(body, stream, target)
        except httpx.HTTPError as e:
            return JSONResponse(
                status_code=502,
                content={"error": {"message": f"中转站不可达：{e}", "type": "upstream_error"}},
            )
        # ★ P2-17 修复：LogType.RELAY（正常转发）原先在整个代码库中
        #   从未被产生，导致日志页「正常转发」筛选项恒为空 ——
        #   一个用户看得见、却永远无结果的选项。防护暂停/未激活期间正是
        #   「未经检测的转发」，如实记录反而是透明度要求。
        #
        # ★ v0.1.0：把「本次实际发给了谁」写进摘要。
        #   多中转站下这是用户唯一能确认账单的依据 ——
        #   没有它，用户只能靠猜。
        host = _extract_host(str((target or {}).get("base_url") or ""))
        via = "按 Key 识别" if matched_by == "key" else "当前启用"
        _record_log(
            LogType.RELAY.value,
            _reputation.reputation_key(
                str((target or {}).get("base_url") or ""),
                str((target or {}).get("api_key") or ""),
            ) if _reputation else "",
            Action.PASS.value,
            "low",
            str(body.get("model", "")),
            [],
            None,
            session_id,
            [],
            text_preview=f"{note}（本次转发给 {host or '-'} · {via}）",
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
            _record_reputation(domain, Action.BLOCK.value, latency_ms, content,
                               categories=_finding_categories(findings))
            return JSONResponse(
                status_code=502,
                content={
                    "error": {
                        "type": "relay_response_blocked",
                        **_blocked_advice(findings),
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
        _record_reputation(domain, action, latency_ms, content,
                           categories=_finding_categories(findings))
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
                            # ★★ 与非流式路径共用 _blocked_advice()：
                            #   两处各写一份文案必然漂移——
                            #   而漂移的后果是「流式能给出路、非流式只给结论」，
                            #   用户换 AI 工具后行为就变了，且没人发现。
                            error_payload = {
                                "error": {
                                    "type": "relay_response_blocked",
                                    **_blocked_advice(result.findings),
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
                # ★ 2026-10-04：落库用**提取后的文本**，而不是 SSE 原文。
                #   此前日志详情的「原始响应片段」显示的是一串
                #   `data: {"id":...,"object":"chat.completion.chunk",...}` ——
                #   用户完全看不懂自己「到底说了什么触发的」。
                #   而同一份数据在验证侧早已通过 _extract_sse_content
                #   提取过，只是没被复用（验证用提取文本、落库用原文，
                #   两条口径分叉，用户看到的是分叉的那一半）。
                readable = _extract_sse_content(joined)
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
                # ★ low 档必须留痕，不能静默 pass：
                #   统计类信号 severity 恒为 low，若映射成 pass，
                #   用户在日志里看不到任何记录 ——
                #   「计数动了却什么都不显示」会让他以为防护根本没开。
                if findings and action == Action.PASS.value:
                    action = Action.ALERT.value
                _record_log(
                    LogType.RESPONSE_VERIFY, domain, action, severity,
                    model, findings, None, session_id, redaction_records,
                    text_preview=readable,
                )
                _record_reputation(domain, action, latency_ms, readable,
                                   categories=_finding_categories(findings))

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
        marked_safe: Optional[bool] = None,
    ):
        """日志列表。`days` 用于文档 4.1 要求的「今天」筛选。"""
        if _storage is None:
            return {"entries": [], "total": 0}
        start_ts = time.time() - days * 86400 if days else None
        entries = _storage.query_logs(
            limit=limit, offset=offset, log_type=log_type,
            action=action, search=search, start_ts=start_ts,
            marked_safe=marked_safe,
        )
        # ★★ total 与 entries 必须用**同一组**过滤条件（2026-10-03 修复）
        #   原实现漏传 search，于是搜索时列表被过滤而计数没被过滤：
        #   搜「你好」只剩 3 条，分页器却显示「共 954 条 / 48 页」，
        #   点第 2 页得到空列表 —— 用户看到的正是「筛不出来」。
        #   query_logs 与 count_logs 的条件必须逐项对齐，
        #   少传任何一项都会让两套口径分叉。
        return {
            "entries": [e.to_dict() for e in entries],
            "total": _storage.count_logs(
                log_type=log_type, action=action, start_ts=start_ts,
                search=search, marked_safe=marked_safe,
            ),
        }

    # ★★ 必须注册在 /api/logs/{log_id} **之前**（2026-10-03 修复）
    #   FastAPI 按注册顺序匹配路由，而 {log_id} 是路径参数：
    #   它会贪婪地吃掉 /api/logs/stats 里的 "stats"，
    #   尝试转成 int 失败 → 422 Unprocessable Entity。
    #   症状极隐蔽：端点明明写好了、函数名也对，
    #   但请求永远到不了它，且报错信息（422）指向"参数格式错"，
    #   与真实原因（路由被抢占）毫无关系。
    #
    #   凡是「静态段 + 参数段」混在同一前缀下，都必须把静态段放前面：
    #   /api/logs/stats、/api/logs/export、/api/logs/clear 都受此约束。
    @app.get("/api/logs/stats")
    async def logs_stats():
        """★ 日志管理页的概览统计（2026-10-03 新增）。

        回答用户真正会问的三件事：「我这些日志都是些什么」
        「有多少是我标记过误报的」「最早记录是什么时候」。
        此前界面上一个数字都没有，用户只能自己翻。
        """
        if _storage is None:
            raise HTTPException(status_code=503, detail="存储未就绪")
        return _storage.log_breakdown()

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

    @app.post("/api/logs/{log_id}/unmark-safe")
    async def unmark_log_safe(log_id: int):
        """撤销误报标记，统计随之加回。

        ★ 必须有这条对称路径。
          标记现在会真的改动 daily_stats（这是本轮修的谎报），
          若只能标不能撤，一次手滑就永久改写了用户的当日统计，
          而界面上根本没有任何入口能改回来 ——
          那就把「谎报」换成了「不可撤销的错误」。
        """
        if _storage is None:
            raise HTTPException(status_code=503, detail="存储未就绪")
        if _storage.get_log(log_id) is None:
            raise HTTPException(status_code=404, detail="日志不存在")
        _storage.unmark_safe(log_id)
        logger.info("日志 %d 已撤销误报标记", log_id)
        return {"ok": True, "log_id": log_id, "marked_safe": False}

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
        _sync_reputation_after_log_delete()
        return {"ok": True, "log_id": log_id}

    @app.post("/api/logs/clear")
    async def clear_logs(before_days: int = Body(0, embed=True)):
        """清空日志。"""
        if _storage is None:
            raise HTTPException(status_code=503, detail="存储未就绪")
        before_ts = time.time() - before_days * 86400 if before_days > 0 else None
        count = _storage.clear_logs(before_ts)
        _sync_reputation_after_log_delete()
        return {"ok": True, "deleted": count}

    @app.post("/api/logs/delete-filtered")
    async def delete_filtered_logs(
        log_type: Optional[str] = None,
        action: Optional[str] = None,
        search: Optional[str] = None,
        days: Optional[int] = Query(None, ge=1, le=365),
        marked_safe: Optional[bool] = None,
    ):
        """★ 按当前筛选条件删除日志（2026-10-03 新增）。

        为什么必须有这个功能：
          此前只有「清空全部」一条路。用户筛出「今天 200 条告警」想清理，
          只能全清 —— 于是要么留着垃圾、要么把有用记录一起删掉。
          「筛选」与「清理」是两个动作，不该绑在一起。

        ★ 安全约束：dry_run 为真时只回报将删除多少条，不真删。
          这是不可恢复的操作，必须让用户先看清范围再确认；
          前端也据此做二次确认。
        """
        if _storage is None:
            raise HTTPException(status_code=503, detail="存储未就绪")
        start_ts = time.time() - days * 86400 if days else None
        filters: Dict[str, Any] = {
            "log_type": log_type, "action": action,
            "search": search, "start_ts": start_ts,
            "marked_safe": marked_safe,
        }
        matched = _storage.count_logs(**filters)
        return {"ok": True, "matched": matched, "deleted": 0, "dry_run": True}

    @app.post("/api/logs/delete-filtered/confirm")
    async def delete_filtered_logs_confirm(
        log_type: Optional[str] = None,
        action: Optional[str] = None,
        search: Optional[str] = None,
        days: Optional[int] = Query(None, ge=1, le=365),
        marked_safe: Optional[bool] = None,
    ):
        """确认执行按筛选条件删除（真正动数据的那一步）。"""
        if _storage is None:
            raise HTTPException(status_code=503, detail="存储未就绪")
        start_ts = time.time() - days * 86400 if days else None
        deleted = _storage.delete_logs(
            log_type=log_type, action=action, search=search,
            start_ts=start_ts, marked_safe=marked_safe,
        )
        _sync_reputation_after_log_delete()
        logger.info("按筛选条件删除日志 %d 条", deleted)
        return {"ok": True, "deleted": deleted, "dry_run": False}

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

        # ★ 直接用模块级函数，不再「为了规范化临时造一个 RelayConfig」——
        #   那样做会让这家的 Key 与地址的对应关系散落在两个地方。
        base = normalize_relay_base(base_url)
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
            # ★★ 多中转站：列表里每一条的 api_key 同样要过掩码守卫。
            #   前端 config.relay 整体回传时，others[].api_key 拿到的
            #   已经是掩码串（见 config.to_safe_dict）——
            #   原实现只守了顶层 api_key，于是用户**每保存一次配置**，
            #   就把其余中转站的真实 Key 全换成 `sk-a…CD⟪…⟫`，
            #   之后切到那家就是 401，而配置页看起来一切正常。
            #   这比「不写 others」严重得多：单中转站时代它不会发生。
            bad = find_masked_key_in_others(payload["relay"].get("others"))
            if bad is not None:
                idx, key = bad
                raise HTTPException(
                    status_code=400,
                    detail=(
                        f"第 {idx + 1} 条中转站配置的 API Key 看起来是脱敏后的串"
                        "（含 ****），已拒绝保存。若这不是你填的，"
                        "说明列表里的 Key 已被掩码污染。"
                    ),
                )
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

    @app.get("/api/relays/configured")
    async def list_relays_conf():
        """★ 已配置的中转站列表（v0.1.0）。

        ★★ 路径必须是 /api/relays/configured，**不能**是 /api/relays。
          /api/relays 已经被「信誉列表」占用了（见上方 list_relays）。
          FastAPI 遇到重复路径不会报错，
          而是**按注册顺序让先注册的那个生效** ——
          新加的同名路由会变成一段永远不被调用的死代码，
          且没有任何异常提示。这类冲突极难发现：
          代码读起来完全正常，只是「接口没生效」。

        与 /api/relays（信誉）**刻意分开**：
          前者答「我配了哪些、现在用哪家」，
          后者答「我用过哪些、它们表现如何」。
          刚填完还没发过对话时信誉表是空的，
          混在一起会让用户以为配置没生效。
        """
        if _config is None:
            raise HTTPException(status_code=503, detail="配置未就绪")
        items = _config.relay.all_relays()
        return {
            "relays": [
                {
                    "id": r.get("id"),
                    "name": r.get("name") or "未命名",
                    "base_url": r.get("base_url") or "",
                    "normalized_base": normalize_relay_base(
                        str(r.get("base_url") or "")),
                    "api_key_masked": mask_relay_key(
                        str(r.get("api_key") or "")),
                    "active": bool(r.get("active")),
                }
                for r in items
            ],
            "active_id": items[0].get("id") if items else "",
        }

    @app.post("/api/relays/configured")
    async def add_relay(payload: Dict[str, Any] = Body(...)):
        """★ 新增一家中转站到列表（不设为启用）。

        ★★ 为什么必须有这个接口：
          多中转站原本只做了「切换」，而 others 只能靠切换产生 ——
          于是**没有任何路径能把第二家加进去**：
          设置页保存的是「当前启用项」，直接改地址等于覆盖原来那家。
          功能看起来存在，实际用户永远只有一家，
          而界面上「已配置的中转站」永远只有一行。
          这类「有渲染、无数据来源」的缺陷在界面上完全看不出来。

        ★ 刻意**不**设为启用项：
          新增即切换会改变用户正在用的目标，
          而他只是「先存着以后用」。
        """
        if _config is None:
            raise HTTPException(status_code=503, detail="配置未就绪")
        relay_cfg = _config.relay

        name = str(payload.get("name") or "").strip() or "未命名"
        base_url = str(payload.get("base_url") or "").strip()
        api_key = str(payload.get("api_key") or "").strip()

        errors: List[str] = []
        if not base_url:
            errors.append("中转站地址不能为空")
        elif not base_url.startswith(("http://", "https://")):
            errors.append("中转站地址必须以 http:// 或 https:// 开头")
        if not api_key:
            errors.append("中转站 API Key 不能为空")
        elif is_masked_key(api_key):
            # 与 update_config 同一条守卫：掩码串绝不能落成真实 Key
            errors.append("这个 API Key 看起来是脱敏后的串（含 ****），已拒绝保存")
        if errors:
            raise HTTPException(status_code=400, detail={"errors": errors})

        new_id = relay_cfg.make_relay_id(base_url, api_key)
        if new_id == relay_cfg.make_relay_id(
                relay_cfg.base_url, relay_cfg.api_key):
            raise HTTPException(
                status_code=400, detail="这家已经是当前使用中的中转站")
        if any(str(r.get("id") or "") == new_id for r in relay_cfg.others):
            raise HTTPException(status_code=400, detail="这家已经在列表里了")

        relay_cfg.others = list(relay_cfg.others) + [{
            "id": new_id, "name": name, "base_url": base_url,
            "api_key": api_key, "enabled": True,
        }]
        _config.save()
        logger.info("已新增中转站到列表: %s（未设为启用）", name)
        return {"ok": True, "id": new_id, "total": len(relay_cfg.others) + 1}

    @app.post("/api/relays/configured/remove")
    async def remove_relay(payload: Dict[str, Any] = Body(...)):
        """从列表里移除一家（**不能**移除当前启用项）。

        ★ 为什么不允许移除启用项：
          移除掉当前在用的那家等于让用户的 AI 工具立刻失去目标，
          而界面上不会有任何提示。必须先「切到这家」。
        """
        if _config is None:
            raise HTTPException(status_code=503, detail="配置未就绪")
        relay_cfg = _config.relay
        want = str(payload.get("id") or "").strip()
        if not want:
            raise HTTPException(status_code=400, detail="缺少中转站 id")
        cur_id = relay_cfg.make_relay_id(relay_cfg.base_url, relay_cfg.api_key)
        if want == cur_id or want == relay_cfg.active_id:
            raise HTTPException(
                status_code=400,
                detail="不能移除当前使用中的中转站，请先切到另一家")

        before = len(relay_cfg.others)
        relay_cfg.others = [
            r for r in relay_cfg.others if str(r.get("id") or "") != want
        ]
        if len(relay_cfg.others) == before:
            raise HTTPException(status_code=404, detail="中转站不存在")
        _config.save()
        logger.info("已从列表移除中转站: %s", want)
        return {"ok": True, "total": len(relay_cfg.others) + 1}

    @app.post("/api/relays/active")
    async def switch_active_relay(payload: Dict[str, Any] = Body(...)):
        """切换当前启用的中转站（显式切换，不做自动故障转移）。

        ★ 切换只改「默认发给谁」，**不删改**任何一条配置。
          原实现把列表里的原始项当成当前项直接覆盖，
          用户切一下就发现原来那家的地址被改了 ——
          再切回去已经不是原来的配置。
        """
        if _config is None:
            raise HTTPException(status_code=503, detail="配置未就绪")
        relay_cfg = _config.relay
        want = str(payload.get("id") or "").strip()
        if not want:
            raise HTTPException(status_code=400, detail="缺少中转站 id")

        # 真正的重排逻辑在 apply_relay_switch（模块级、可被测试直接调用）。
        # 路由只负责翻译错误码 —— 把算法写在这里会让它无法被单独验证，
        # 而这类「切换后配置被改坏」的 bug 恰恰只在真切换一次时才暴露。
        try:
            result = apply_relay_switch(relay_cfg, want)
        except KeyError:
            raise HTTPException(status_code=404, detail="中转站不存在")

        errors = _config.validate()
        if errors:
            raise HTTPException(status_code=400, detail={"errors": errors})
        _config.save()
        logger.info("已切换当前中转站，启用 id=%s", result["active_id"])
        return {"ok": True, "active_id": result["active_id"]}

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
            # ★ 必须与 /api/relays 的 domain 用同一个键（含 Key 指纹），
            #   否则前端按域名匹配「当前中转站」时永远匹配不上，
            #   卡片会一直显示「已配置 · 尚未产生调用记录」。
            "relay_domain": (
                _reputation.reputation_key(
                    _config.relay.base_url, _config.relay.api_key,
                )
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

    ★★ low 档必须返回 ALERT 而不是 PASS（2026-10-03）
      统计类信号（长度/结构突变）在 v0.1.1 起severity 恒为 low，
      若low 仍映射成 PASS，用户在日志里看不到任何记录 ——
      「计数动了却什么都不显示」比「有提示但不好看」更糟：
      它会让用户以为防护根本没开。
    """
    if max_sev == "low":
        # 有发现项才提示；确实一个发现都没有时才是真的 pass
        return Action.PASS.value if not verify_result else Action.ALERT.value
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


def _blocked_advice(findings: List[Any]) -> Dict[str, Any]:
    """生成阻断时给用户的 error 字段。

    ★★ 这里决定用户被拦住之后会看到什么（v0.1.1）
    ────────────────────────────────────────────────────────────
    原文只有一句「响应含高危内容」。用户正等着 AI 把活干完，
    被拦住却既不知道发生了什么，也不知道该做什么 —— 这是最糟的形态：
    产品既没保护好他，也没能帮他继续。

    真实处境是：用户无法修中转站（那是他花钱买的第三方服务），
    但手上有必须完成的任务。所以唯一有用的出路是
    **把任务换到官方 API 上继续做**，顺带让他判断是否误报。

    报哪一条也有讲究：优先报非统计类的命中。
    「本次长度偏离历史均值 124σ」用户看不懂，说了只会更困惑；
    「中转站调用了你没声明的工具」他能立刻判断对不对。
    """
    hit = next(
        (f for f in findings if getattr(f, "category", "") not in _STATISTICAL_SIGNALS),
        None,
    )
    if hit is None:
        hit = findings[0] if findings else None
    reason = getattr(hit, "detail", "") or "响应含高危内容"

    advice = (
        f"玄盾拦下了这次响应（{reason}）。"
        "当前中转站被判定不可信，它可能已经影响了回答质量。"
        "如果任务还没完成，建议把 AI 工具的 API 地址改回模型厂商官方地址继续做，"
        "或在设置页换一家中转站后重试。这段对话在换地址前无法继续。"
    )
    return {
        "message": advice,
        "advice": advice,
        "reason": reason,
        "categories": sorted({
            getattr(f, "category", "") for f in findings if getattr(f, "category", "")
        }),
    }


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


def _headline_detail(findings: List[Any]) -> str:
    """挑出该当头条的那条 detail。

    ★ 为什么不直接取 findings[0]（2026-10-04）
      检测器产出 findings 的顺序是**内部实现顺序**，与「哪个重要」无关。
      实测用户日志 #1250：摘要写着「响应结构与历史显著不同，仅作记录，
      不阻断」，而这条日志实际被**阻断**了 —— 因为同一批里还有一条
      「工具调用参数中出现疑似 typosquat 的依赖包」。
      摘要说「不阻断」、处置是「阻断」，用户唯一能得出的结论是软件坏了。

    ★ 规则：优先取**非观测类**的发现项（它们才是处置的依据）；
      整批都是观测类时，才退回取第一条。
    """
    for f in findings:
        if getattr(f, "category", "") not in OBSERVATION_ONLY_SIGNALS:
            return str(getattr(f, "detail", "") or "")
    return str(getattr(findings[0], "detail", "") or "")


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
        summary = _headline_detail(findings) if findings else "正常转发"
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


def find_masked_key_in_others(
    others: Optional[List[Any]],
) -> Optional[Tuple[int, str]]:
    """在中转站列表里找出第一个「掩码串冒充真 Key」的条目。

    ★ 为什么必须单独抽出来：
      这条守卫的失效后果是**静默且不可逆** ——
      用户每点一次「保存中转站配置」，其余中转站的真实 Key
      就被替换成 `sk-a…CD⟪…⟫` 落进磁盘；之后切到那家必然 401，
      而配置页显示一切正常，用户只会以为中转站封了他。

    ★ 判据放在模块级而非路由闭包内：
      写在闭包里就只能靠「读源码找 is_masked_key 字样」来判断，
      而那种判据是恒真的 —— 把判断条件改掉、字样还在，测试照样绿。

    Returns: (下标, 该条的值)；没有则 None
    """
    for i, item in enumerate(others or []):
        if not isinstance(item, dict):
            continue
        key = str(item.get("api_key") or "")
        if is_masked_key(key):
            return i, key
    return None


def resolve_forward_target(
    target: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """把「转发给哪家」解析成真正要用的接入地址与 Key。

    ★★ 这是「账单打不错」的最后一道关。
      历史实现是「先按 Key 识别出目标，转发时又用配置里的
      启用 Key 无条件覆盖 Authorization」——
      识别对了却在最后一步被推平，结果是拿 A 的 Key 请求 B 的地址。

    ★ 抽成模块级纯函数的原因同 apply_relay_switch：
      闭包内的写法无法被测试直接调用，
      只能靠「读源码确认没有 `_config.relay.api_key`」来判断 ——
      而那种判据是恒真的，把赋值挪个位置照样绿。

    Returns: {"base": 规范化后的地址, "api_key": 该家的 Key, "relay": 原项}
    """
    if _config is None:
        raise httpx.ConnectError("代理未初始化")
    relay_cfg = _config.relay
    if target is None:
        target = relay_cfg.all_relays()[0]
    return {
        "base": normalize_relay_base(str(target.get("base_url") or "")),
        # 目标缺 Key 时才回落 —— 回落方向必须是「启用的那把」，
        # 绝不能反过来无条件覆盖成启用项的 Key。
        "api_key": str(target.get("api_key") or relay_cfg.api_key),
        "relay": target,
    }


def _resolve_upstream(request) -> Optional[Dict[str, Any]]:
    """按请求带来的 Key 判定「这次该转发给哪家」。

    ★★ 刻意**不是** async —— 这里只读 header 与配置，不做任何 I/O。
      原实现写成 `async def` 而调用处忘了 await，
      于是拿到的是一个 coroutine 对象，`resolved.get("relay")` 直接抛
      AttributeError → 每个 AI 请求 500。
      单元测试当时全绿是因为它们只调 `_resolve_upstream` 自己
      （自己包了 asyncio.run），从没走调用点 ——
      这类「只在拼装处才暴露」的错误必须由端到端用例兜住。

    ★★ 这是多中转站里最关键的一步。
      原实现无条件用配置里的 api_key 覆盖 Authorization，
      于是「AI 工具里填 A 家、玄盾里配 B 家」时，
      用户以为在用 A 扣费，实际扣的是 B ——
      账单打错，而且两边都不知道。

    ★ 判定顺序
      1) 请求带了 Authorization → 去掉 "Bearer " 前缀后按 Key 匹配；
      2) 命中已配置的中转站 → 用那家的地址与 Key；
      3) 没命中（老配置只有一家，或用户刚换了 Key）
         → 回退到当前启用项，并把实际用的那家回报给调用方，
            让日志与界面能显示「本次实际转发给了谁」。

    ★ 不做自动故障转移、不做轮询：
      探活是真实 HTTP 请求，本机平均延迟 13 秒，
      拿它做后台探测等于持续制造慢请求；
      而自动切换会让「这次扣了谁的钱」变得不可知 ——
      多中转站场景下最需要确定的就是这件事。

    Returns: {"relay": {...}, "matched_by": "key"|"active"}；无配置时 None
    """
    if _config is None:
        return None
    relay_cfg = _config.relay
    incoming = ""
    auth = request.headers.get("Authorization") or ""
    if auth.lower().startswith("bearer "):
        incoming = auth[7:].strip()

    matched = relay_cfg.relay_by_key(incoming) if incoming else None
    if matched is not None:
        logger.info(
            "按 Key 识别到中转站：%s（%s）",
            matched.get("name") or "-", _extract_host(matched.get("base_url")),
        )
        return {"relay": matched, "matched_by": "key"}

    return {"relay": relay_cfg.all_relays()[0], "matched_by": "active"}


def apply_relay_switch(relay_cfg, want: str) -> Dict[str, Any]:
    """把 id 为 want 的那家提为当前启用项，其余留在列表里。**就地修改** relay_cfg。

    ★★ 必须**重排**而不是覆盖，这是本轮最容易写坏的地方。
      原实现（也是最容易写出的直觉写法）是把目标项直接赋给
      base_url/api_key/name，再把 others 清空或原样留着 ——
      结果：用户切一下，原来那家的地址就被覆盖了，
      再切回去已经不是它；而目标项还留在 others 里，成了重复项。

      正确形态：旧当前项 → 备份进列表尾部；目标项 → 提为当前项；
      其余项原序保留。切换前后「地址 + Key」的集合必须完全相同。

    ★ 为什么抽成模块级纯函数：
      路由里的闭包无法被测试直接调用，于是这类结构性错误
      只能靠「读源码找字符串」来判断 —— 而那种判据是恒真的：
      把赋值改坏、字符串都还在，测试照样绿。
      抽出来后测试能真的切换一次并逐字段核对。

    Returns: {"ok": bool, "active_id": str, "changed": bool}
    Raises: KeyError —— want 不在列表里
    """
    cur_id = relay_cfg.make_relay_id(relay_cfg.base_url, relay_cfg.api_key)
    if want == cur_id:
        return {"ok": True, "active_id": want, "changed": False}

    target = next(
        (r for r in relay_cfg.others
         if str(r.get("id") or "") == want), None)
    if target is None:
        raise KeyError(want)

    new_active = {
        "id": relay_cfg.make_relay_id(
            str(target.get("base_url") or ""),
            str(target.get("api_key") or ""),
        ),
        "name": str(target.get("name") or "未命名"),
        "base_url": str(target.get("base_url") or ""),
        "api_key": str(target.get("api_key") or ""),
        "enabled": bool(target.get("enabled", True)),
    }
    current_backup = {
        "id": cur_id,
        "name": relay_cfg.name,
        "base_url": relay_cfg.base_url,
        "api_key": relay_cfg.api_key,
        "enabled": relay_cfg.enabled,
    }
    remaining = [
        r for r in relay_cfg.others if str(r.get("id") or "") != want
    ]
    relay_cfg.base_url = new_active["base_url"]
    relay_cfg.api_key = new_active["api_key"]
    relay_cfg.name = new_active["name"]
    relay_cfg.enabled = new_active["enabled"]
    relay_cfg.active_id = new_active["id"]
    relay_cfg.others = [current_backup] + remaining
    return {"ok": True, "active_id": new_active["id"], "changed": True}


def _extract_host(url: str) -> str:
    """取地址里的主机名（日志用，避免把完整 URL 和 Key 混在一行）。"""
    try:
        from urllib.parse import urlparse
        return urlparse(url or "").hostname or ""
    except Exception:  # noqa: BLE001
        return ""


def _record_reputation(
    domain: str,
    action: str,
    latency_ms: float,
    content: str,
    categories: Optional[List[str]] = None,
) -> None:
    """更新中转站信誉。

    ★ categories 决定这次风险算谁头上（见 tracker._classify）。
      不传就退化成「全算用户自己的」——
      宁可漏扣也不在无证据时指控中转站。

    ★★ domain 必须由调用方传入「本次实际转发的那家」的域名。
      原实现用 `_config.relay.base_url` —— 那是**当前启用项**，
      不是这次请求发去的地方。多中转站下会把 B 家的风险
      记到 A 家头上：用户明明用 B，一次异常就把 A 的分数打下去，
      而 A 什么都没做。这是本轮最隐蔽的一处归因错误，
      因为单中转站时代它完全正确（两者是同一个东西）。
      domain 为空时才回退到启用项（老调用点兼容）。
    """
    if _reputation is None or _config is None:
        return
    if not domain:
        # ★ 用 getattr 而不是直接取属性：老配置对象/测试桩可能没有
        #   api_key 字段，直接取会抛 AttributeError 并让整条转发失败。
        domain = _reputation.reputation_key(
            _config.relay.base_url,
            getattr(_config.relay, "api_key", "") or "",
        )
    if not domain:
        return
    try:
        rep = _reputation.record_call(
            domain if domain.startswith("http") else f"https://{domain}",
            action, latency_ms, content,
            categories=categories,
        )
        if _storage is not None:
            _storage.upsert_reputation(rep)
    except Exception as e:  # noqa: BLE001
        logger.warning("信誉记录失败: %s", e)


def _finding_categories(findings) -> List[str]:
    """从 findings 里取出检测项类别，供信誉归因使用。"""
    return [f.category for f in findings if getattr(f, "category", "")]


def _migrate_relay_keys_to_fingerprint() -> None:
    """把旧的「纯主机」信誉键升级为「主机#Key指纹」（2026-10-04，一次性）。

    ★ 为什么只在**无歧义**时迁移
      该主机在配置里只对应一家 → 旧记录必然属于它，迁移是确定的。
      同一主机配了多个账号时，旧记录没存指纹、信息上拆不开 ——
      强行归给其中一家会把另一家的账也记上去，比不迁移更糟。
      这类记录保持原样（仍按主机聚合），用户下次发请求时各自建立新键。

    ★ 幂等
      迁移后旧键不再存在，重复执行是空操作。

    ★ 失败不阻断启动
      迁移只是数据整理；失败时旧的按主机聚合仍然可用。
    """
    if _storage is None or _config is None:
        return
    try:
        by_netloc: Dict[str, List[str]] = {}
        for r in _config.relay.all_relays():
            base = str(r.get("base_url") or "")
            netloc = ReputationTracker.extract_domain(base)
            key = ReputationTracker.reputation_key(
                base, str(r.get("api_key") or "")
            )
            if netloc and key and key != netloc:
                by_netloc.setdefault(netloc, []).append(key)

        moved = 0
        ambiguous = 0
        for netloc, keys in by_netloc.items():
            if len(keys) != 1:
                ambiguous += 1
                continue
            moved += _storage.migrate_relay_key(netloc, keys[0])["logs"]
        if moved:
            logger.info("信誉键升级为含 Key 指纹：迁移 %d 条记录", moved)
        if ambiguous:
            logger.info(
                "%d 个主机下配了多个账号，其历史记录无法拆分，"
                "保持按主机聚合（新调用将分别计数）", ambiguous,
            )
    except Exception as e:  # noqa: BLE001 — 迁移失败不该阻断启动
        logger.warning("信誉键迁移失败（不影响使用）: %s", e)


def _sync_reputation_after_log_delete() -> None:
    """删日志后把中转站计数按剩余日志重算（2026-10-04）。

    ★ 为什么必须有
    ────────────────────────────────────────────────────────────
    relay_reputation 的计数是**累加**值，而首页 KPI 是从 logs 实时算的。
    删日志只影响后者，于是「清空日志后首页归零、中转站卡片
    还写着 3 次调用」—— 两个数字都"对"，口径不同，用户只看到矛盾。
    实测（2026-10-04）：

        清空日志后   首页今日调用 3 → 0 ✓
                     中转站卡片总调用 3 → 3 ✗

    ★ 为什么放在路由层而不是 storage 层：
      重算需要 _classify（谁的责任）与 _compute_score（扣多少分），
      两者都在 reputation/tracker.py。让 storage 反向依赖 tracker
      会把分层倒过来；由路由层编排 pump 一次即可。

    ★ 失败只告警不抛错：
      「删日志」已经成功落库了，同步失败不该让用户看到删除报错 ——
      那会让他以为没删掉，然后反复删。下次删除或重启会再对齐一次。
    """
    if _reputation is None or _storage is None:
        return
    try:
        _reputation.rebuild_from_facts(_storage.iter_log_facts())
        for rep in _reputation.list_all():
            _storage.upsert_reputation(rep)
    except Exception as e:  # noqa: BLE001 — 同步失败不影响删除结果
        logger.warning("中转站计数同步失败（不影响本次删除）: %s", e)


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

    # ★ 记下实际端口，供 lifespan 的日志使用（见 _actual_port 注释）
    global _actual_port
    _actual_port = int(actual_port)

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
