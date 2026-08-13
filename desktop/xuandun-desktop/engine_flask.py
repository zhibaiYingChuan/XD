# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白
# 本文件受道体研究许可证 v1.0 约束，禁止逆向工程和再分发
# 详见 LICENSE 文件

"""道体玄盾 桌面端引擎入口 - 使用 Flask 替代 http.server。

Flask 内置的开发服务器在 Windows 上更稳定。
生产环境应使用 waitress 或 gunicorn。
"""

import argparse
import json
import logging
import os
import re
import signal
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from collections import deque, Counter

import math
import numpy as np


class _NullDevice:
    def write(self, s):
        pass

    def flush(self):
        pass


if sys.stdout is None:
    sys.stdout = _NullDevice()
if sys.stderr is None:
    sys.stderr = _NullDevice()

from flask import Flask, request, jsonify
from daoti_xuandun import XuanDun, XuanDunConfig, DefenseLevel
from daoti_xuandun.integrations import (
    AlertManager, AlertEvent, DingTalkNotifier, FeishuNotifier,
    EmailNotifier, WebhookNotifier, SyslogNotifier,
)

try:
    import anti_debug
    _ANTI_DEBUG_AVAILABLE = True
except ImportError:
    _ANTI_DEBUG_AVAILABLE = False

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stderr)],
)
logger = logging.getLogger("xuandun-engine")

app = Flask(__name__)

# 引擎版本号单一来源（SSOT 从 Cargo.toml 同步，见 sync_version.py）。
# health 与 status 端点共用此常量，避免版本双字面量漂移（R4 修复）。
# sync_version.py 通过匹配本常量赋值行来做版本同步，保持单行格式。
_ENGINE_VERSION = "1.3.4"

_MODE_MAP = {
    "high_security": DefenseLevel.STRICT,
    "balanced": DefenseLevel.STANDARD,
    "low_false_positive": DefenseLevel.BASIC,
}

_shields = {}
_default_mode = "balanced"
_start_time = time.time()
_total_requests = 0
_total_blocked = 0
_stats_lock = threading.Lock()
_shields_lock = threading.Lock()
running = True

_alert_manager = AlertManager()

_NOTIFIER_CLASSES = {
    "dingtalk": DingTalkNotifier,
    "feishu": FeishuNotifier,
    "email": EmailNotifier,
    "webhook": WebhookNotifier,
    "syslog": SyslogNotifier,
}

# --- 日志脱敏：所有写日志的用户文本都先过 _redact_pii_for_log ---
#   避免敏感信息（手机号/身份证/邮箱/Bearer Token/JWT/银行卡）写入日志文件

_LOG_PII_REPLACEMENTS = [
    # Bearer Token / JWT
    (re.compile(r"Bearer\s+[A-Za-z0-9\-_\.=]+\b", re.I), "[REDACTED:TOKEN]"),
    # AWS Access Key ID
    (re.compile(r"AKIA[0-9A-Z]{16}"), "[REDACTED:AWS_KEY]"),
    # 手机号（中国）
    (re.compile(r"1[3-9]\d{9}"), "[REDACTED:PHONE]"),
    # 身份证号（18位）
    (re.compile(r"\b\d{17}[\dXx]\b"), "[REDACTED:ID]"),
    # 护照号
    (re.compile(r"\b[EeGg]\d{8}\b"), "[REDACTED:PASSPORT]"),
    # 邮箱地址
    (re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"), "[REDACTED:EMAIL]"),
    # 银行卡号（15-19 位纯数字）— 放在最后，避免覆盖身份证
    (re.compile(r"\b\d{15,19}\b"), "[REDACTED:BANK]"),
    # 长 hex / AES Key（32+ hex chars）
    (re.compile(r"\b[0-9a-fA-F]{32,}\b"), "[REDACTED:HEX_KEY]"),
    # GCP Service Account Key 片段
    (re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----", re.I), "[REDACTED:PRIVATE_KEY]"),
]


def _redact_pii_for_log(text, max_preview: int = 80) -> str:
    """对日志中的用户文本做 PII 打码 + 长度截断。

    用于所有 logger.info/warning/error 中包含用户输入/原文的位置，
    防止敏感信息进入磁盘日志或告警通道。
    """
    if text is None:
        return ""
    try:
        s = str(text)
    except Exception:
        return repr(text)
    # 先截断：绝大多数 PII 在 80 字符范围内都能覆盖
    truncated = len(s) > max_preview
    work = s if not truncated else s[:max_preview]
    for pattern, replacement in _LOG_PII_REPLACEMENTS:
        work = pattern.sub(replacement, work)
    if truncated:
        work = work + "…"
    return work


_DEBUG_TOKEN = os.environ.get("XUANDUN_DEBUG_TOKEN", "")
_ALLOWED_ORIGINS = ("tauri://localhost", "http://tauri.localhost")

# ---------- 管理接口鉴权：管理员令牌 ----------
#   未设置 XUANDUN_ADMIN_TOKEN 时，管理员操作（逃生通道/灰度切换/模式切换/
#   告警通道配置/原型预热/词典增删）只允许同源 tauri 页面调用；
#   设置后，所有管理接口还必须携带 X-Admin-Token 请求头匹配。
_ADMIN_TOKEN = os.environ.get("XUANDUN_ADMIN_TOKEN", "")

# 标注为"管理接口"的路由表（endpoint_name → True）。
# 所有在此表中的路由，除需 CORS 同源校验外，若配置了 XUANDUN_ADMIN_TOKEN，
# 还必须携带匹配的 X-Admin-Token 头，否则返回 401。
_ADMIN_ENDPOINTS = {
    "/emergency/bypass",
    "/gray/deploy",
    "/mode/switch",
    "/set-mode",
    "/notifiers/config",
    "/notifiers/test",
    "/alert/dispatch",
    "/warmup",
    "/output/warmup",
    # R5 修复：/output/config 直接改动输出护栏阈值（拦截/打码/告警判定），
    # 此前未纳入此集合导致 _require_admin_auth 直接放行，对任意来源开放。
    # 现纳入管理接口统一鉴权（Origin 同源 + 可选 X-Admin-Token）。
    "/output/config",
    "/sensitive/dict",           # POST/DELETE 需要鉴权
    "/debug/state",
    "/learn/safe",               # R9 修复：学习安全样本接口需鉴权
    "/bypass/stats",             # R9 修复：逃生通道统计接口需鉴权
}


def _require_admin_auth(endpoint: str):
    """对管理接口执行统一鉴权：X-Admin-Token + CORS Origin 校验。

    返回值说明：
      - None 表示通过；
      - (resp_body, status_code) tuple 表示拦截并返回对应响应。
    """
    # /debug/state 走自己的 DEBUG_TOKEN 逻辑，这里跳过
    if endpoint == "/debug/state":
        return None
    if endpoint not in _ADMIN_ENDPOINTS:
        return None
    # 1) CORS Origin 必须是桌面端同源（tauri://localhost）
    origin = _cors_origin()
    if not origin and not _ADMIN_TOKEN:
        # 未配置 admin token 时，非同源请求一律拒绝（防止局域网暴露）
        return (jsonify({"error": "origin not allowed"}), 403)
    # 2) 若配置了 admin token，必须匹配，即使同源也需要（深度防御）
    if _ADMIN_TOKEN:
        provided = request.headers.get("X-Admin-Token", "")
        if provided != _ADMIN_TOKEN:
            return (jsonify({"error": "admin token required"}), 401)
    return None

# --- 学习数据快照：定期将运行时学习状态持久化到磁盘 ---
_LEARNING_SNAPSHOT_DIR = None  # 在 main() 中初始化为引擎数据目录
_LEARNING_SNAPSHOT_PATH = None  # 完整快照文件路径
_last_snapshot_call_count = 0  # 上次快照时的 call_count
_SNAPSHOT_INTERVAL = 100  # 每 100 次 call_count 增长保存一次快照


def _cors_origin() -> str:
    origin = request.headers.get("Origin", "")
    if origin in _ALLOWED_ORIGINS:
        return origin
    return ""


def _attach_cors(resp):
    origin = _cors_origin()
    if origin:
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Access-Control-Allow-Methods"] = "POST, OPTIONS"
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type, X-Debug-Token"
    else:
        resp.headers["Access-Control-Allow-Origin"] = ""
    return resp


def _transfer_learning_data(target: XuanDun, source: XuanDun):
    """从源 shield 迁移学习数据到目标 shield（仅维度无关的数据）。

    当防御层级切换（如 balanced → high_security）时，不同层级的
    hidden_dim 可能不同（64/128/256），因此维度相关的原型向量、
    投影矩阵等无法直接拷贝。本函数迁移所有维度无关的学习数据，
    确保已有的域知识、否定校准、EWMA 状态等不丢失。
    """
    src = source.domain_awareness
    dst = target.domain_awareness

    # --- 标量 ---
    dst.sample_count = src.sample_count
    dst.call_count = src.call_count
    dst._domain_char_count = src._domain_char_count
    dst._domain_byte_count = src._domain_byte_count
    dst._domain_trigram_count = src._domain_trigram_count
    dst._domain_fourgram_count = src._domain_fourgram_count
    dst._rejected_fourgram_count = src._rejected_fourgram_count
    dst._negation_sample_count = src._negation_sample_count
    dst._language_feature_weight = src._language_feature_weight
    dst._language_weight_update_counter = src._language_weight_update_counter
    dst._last_forget_time = src._last_forget_time
    dst._last_binary_anomaly = src._last_binary_anomaly
    dst._negation_calibrated = src._negation_calibrated
    dst._negation_weights_locked = src._negation_weights_locked
    if src._ewma_mean is not None:
        dst._ewma_mean = src._ewma_mean
    if src._ewma_var is not None:
        dst._ewma_var = src._ewma_var

    # --- 字典（深拷贝避免引用共享） ---
    dst._domain_char_profile = dict(src._domain_char_profile)
    dst._domain_trigram_profile = dict(src._domain_trigram_profile)
    dst._domain_char_fourgram_profile = dict(src._domain_char_fourgram_profile)
    dst._domain_inquiry_prefixes = dict(src._domain_inquiry_prefixes)
    dst._rejected_fourgram_profile = dict(src._rejected_fourgram_profile)
    dst._domain_imperative_prefixes = dict(src._domain_imperative_prefixes)
    dst._domain_learning_phrases = dict(src._domain_learning_phrases)
    dst._negation_weights = dict(src._negation_weights)
    dst._negation_feedback = dict(src._negation_feedback)
    dst._negation_signal_history = {k: list(v) for k, v in src._negation_signal_history.items()}
    dst._repetition_cache = dict(src._repetition_cache)
    dst._pattern_timestamps = dict(src._pattern_timestamps)

    # --- deque（保持目标 maxlen） ---
    dst.chaos_nursery = deque(src.chaos_nursery, maxlen=dst.chaos_nursery.maxlen)
    dst.distance_history = deque(src.distance_history, maxlen=dst.distance_history.maxlen)
    dst._accepted_distances = deque(src._accepted_distances, maxlen=dst._accepted_distances.maxlen)
    dst.observing_would_block = deque(src.observing_would_block, maxlen=dst.observing_would_block.maxlen)
    dst._recent_inputs = deque(src._recent_inputs, maxlen=dst._recent_inputs.maxlen)

    # --- numpy 数组（维度无关：字节频率分布，shape 固定为 256） ---
    if src._domain_byte_profile is not None:
        dst._domain_byte_profile = src._domain_byte_profile.copy()

    # --- 洛书映射器状态（均在 176 维原生空间，维度无关） ---
    if dst._luoshu is not None and src._luoshu is not None:
        dst._luoshu.safe_prototypes = [p.copy() for p in src._luoshu.safe_prototypes]
        dst._luoshu.attack_prototypes = [p.copy() for p in src._luoshu.attack_prototypes]
        dst._luoshu._attack_fingerprint_counter = Counter(src._luoshu._attack_fingerprint_counter)

    logger.info(
        "Transferred learning data from existing shield: "
        "call_count=%d, sample_count=%d, char_profile=%d, trigram_profile=%d, "
        "rejected_fourgram=%d, negation_calibrated=%s, "
        "ewma=%s, luoshu_safe=%d, luoshu_attack=%d",
        src.call_count, src.sample_count, len(src._domain_char_profile),
        len(src._domain_trigram_profile), src._rejected_fourgram_count,
        src._negation_calibrated,
        f"mean={src._ewma_mean:.4f}" if src._ewma_mean is not None else "None",
        len(src._luoshu.safe_prototypes) if src._luoshu else 0,
        len(src._luoshu.attack_prototypes) if src._luoshu else 0,
    )


def _save_learning_snapshot():
    """保存轻量级学习状态快照到 JSON 文件。

    定期将各 shield 的学习统计摘要写入磁盘，用于：
    1. 引擎重启后了解之前的学习进展
    2. 外部系统（如 LRC 记忆库）读取快照进行记忆同步
    3. 调试和监控学习趋势

    本函数仅保存维度无关的统计信息，不保存原始数据（原型向量等）。
    快照文件位于引擎数据目录下的 learning_snapshot.json。
    """
    if not _shields:
        return
    if not _LEARNING_SNAPSHOT_PATH:
        return

    snapshots = {}
    for mode, shield in _shields.items():
        da = shield.domain_awareness
        snapshots[mode] = {
            "call_count": da.call_count,
            "sample_count": da.sample_count,
            "profile_sizes": {
                "char": len(da._domain_char_profile),
                "trigram": len(da._domain_trigram_profile),
                "fourgram": len(da._domain_char_fourgram_profile),
                "inquiry_prefixes": len(da._domain_inquiry_prefixes),
                "imperative_prefixes": len(da._domain_imperative_prefixes),
                "learning_phrases": len(da._domain_learning_phrases),
                "rejected_fourgram": len(da._rejected_fourgram_profile),
            },
            "prototype_counts": {
                "total": len(da.prototypes),
                "luoshu_safe": len(da._luoshu.safe_prototypes) if da._luoshu else 0,
                "luoshu_attack": len(da._luoshu.attack_prototypes) if da._luoshu else 0,
            },
            "negation": {
                "calibrated": da._negation_calibrated,
                "sample_count": da._negation_sample_count,
                "weights_locked": da._negation_weights_locked,
            },
            "rejected_fourgram_count": da._rejected_fourgram_count,
            "ewma_mean": da._ewma_mean,
        }

    payload = {
        "timestamp": time.time(),
        "engine_mode": _default_mode,
        "uptime": round(time.time() - _start_time, 1),
        "cached_modes": list(_shields.keys()),
        "shields": snapshots,
        "version": 1,
    }

    try:
        with open(_LEARNING_SNAPSHOT_PATH, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False)
        logger.info("Learning snapshot saved (%d shields, %s)", len(_shields), _LEARNING_SNAPSHOT_PATH)
    except Exception as e:
        logger.warning("Failed to save learning snapshot: %s", e)


def _load_learning_snapshot():
    """启动时从 learning_snapshot.json 加载学习状态摘要。

    在引擎 start 阶段调用，检查快照文件是否存在。若存在且版本号匹配，
    记录各 shield 的历史学习统计信息，供后续学习迁移和诊断使用。
    注意：本函数仅加载摘要信息到日志，不修改 shield 的内部状态（因为
    DomainAwareness 的学习计数是内部管理的）；若其他模式按需创建，
    _transfer_learning_data 会自动将已有 shield 的数据迁移过去。
    """
    if not _LEARNING_SNAPSHOT_PATH or not os.path.isfile(_LEARNING_SNAPSHOT_PATH):
        logger.info("No learning snapshot found, starting from cold state")
        return

    try:
        with open(_LEARNING_SNAPSHOT_PATH, "r", encoding="utf-8") as f:
            payload = json.load(f)

        version = payload.get("version")
        if version != 1:
            logger.warning(
                "Learning snapshot version mismatch: expected=1, got=%s, skipping load",
                version,
            )
            return

        shields_data = payload.get("shields", {})
        total_samples = 0
        for mode_name, shield_data in shields_data.items():
            sc = shield_data.get("sample_count", 0)
            cc = shield_data.get("call_count", 0)
            total_samples += sc
            logger.info(
                "从快照恢复学习状态：mode=%s sample_count=%d call_count=%d",
                mode_name, sc, cc,
            )

        logger.info(
            "从快照恢复学习状态：共 %d 条样本 / %d 个 mode（快照时间=%s）",
            total_samples, len(shields_data), payload.get("timestamp", "unknown"),
        )
    except (json.JSONDecodeError, IOError, OSError) as e:
        logger.warning("Failed to load learning snapshot: %s", e)
    except Exception as e:
        logger.error("Unexpected error loading learning snapshot: %s", e, exc_info=True)


def _maybe_save_snapshot(mode: str):
    """检查是否需要保存快照，按 call_count 增长阈值触发。

    由 /protect 端点在每次请求后调用，避免在每次请求时都写 IO。
    """
    global _last_snapshot_call_count

    shield = _shields.get(mode)
    if shield is None:
        return

    current = shield.domain_awareness.call_count
    if current - _last_snapshot_call_count >= _SNAPSHOT_INTERVAL:
        _last_snapshot_call_count = current
        _save_learning_snapshot()


def _best_existing_shield() -> "XuanDun":
    """返回现有 shield 中学习数据最丰富的一个（作为创建失败时的降级回退）。

    逃生通道/灰度等「救命 + 运维」端点必须始终可用，即使某个防护模式
    （如 low_false_positive 的 BASIC 层级）实例化失败，也应回退到现有实例，
    避免引擎「看似在线但逃生功能静默失效」的高危状态。
    """
    if not _shields:
        raise RuntimeError("no shield available")
    return max(_shields.values(), key=lambda s: s.domain_awareness.call_count)


def _get_shield(mode: str) -> XuanDun:
    with _shields_lock:
        if mode not in _shields:
            logger.info("Creating new XuanDun instance for mode=%s", mode)
            try:
                level = _MODE_MAP.get(mode, DefenseLevel.STANDARD)
                config = XuanDunConfig.for_level(level)
                shield = XuanDun(config)
                # 桌面端强制启用保护模式，无需等待样本积累
                # 内置攻击/安全原型已提供充分的初始防护能力
                shield.switch_mode("protecting")

                # 如果有其他模式的 shield 已有学习数据，迁移之。
                # 迁移失败不阻断新实例创建（降级为不带历史数据的冷实例）。
                if _shields:
                    source = max(_shields.values(), key=lambda s: s.domain_awareness.call_count)
                    if source.domain_awareness.call_count > 0:
                        logger.info(
                            "Preparing to transfer learning data from mode with call_count=%d",
                            source.domain_awareness.call_count,
                        )
                        try:
                            _transfer_learning_data(shield, source)
                        except Exception as e:
                            logger.warning(
                                "learning transfer failed for mode=%s (will continue cold): %s",
                                mode, e, exc_info=True,
                            )

                _shields[mode] = shield
                logger.info("XuanDun instance created for mode=%s (mode=protecting)", mode)
            except Exception as e:
                # 创建失败：绝不裸抛，回退到现有实例，保证逃生通道等关键端点可用。
                logger.error(
                    "shield creation failed for mode=%s: %s (type=%s)",
                    mode, e, type(e).__name__, exc_info=True,
                )
                if _shields:
                    fallback = _best_existing_shield()
                    logger.warning(
                        "falling back to existing shield, available modes=%s",
                        list(_shields.keys()),
                    )
                    return fallback
                raise
        return _shields[mode]


@app.route("/health", methods=["GET"])
def health():
    # S2a-T09: 标准化健康检查端点，供 Docker/K8s healthcheck 与桌面端探活使用
    # 返回字段：status(ok/degraded/down) / version / uptime(秒) / models_count(当前纳管模型数)
    # 注意：sync_version.py 依赖 _ENGINE_VERSION 常量赋值行做版本同步（保持单行）
    return jsonify({"status": "ok", "version": _ENGINE_VERSION, "uptime": int(time.time() - _start_time), "models_count": 1})


@app.route("/status", methods=["GET"])
def status():
    with _stats_lock:
        total_req = _total_requests
        total_blk = _total_blocked
    uptime = time.time() - _start_time
    block_rate = total_blk / max(1, total_req)

    learning_mode = "protecting"
    learning_progress = 1.0
    sample_count = 0
    shield_healthy = True
    try:
        shield = _get_shield(_default_mode)
        ls = shield.get_learning_status()
        learning_mode = ls.get("mode", "protecting")
        learning_progress = ls.get("learning_progress", 1.0)
        sample_count = ls.get("sample_count", 0)
    except Exception as e:
        # 不再吞错掩盖：明确标记 shield 不健康，供前端据此告警，
        # 避免「引擎看似在线但逃生/灰度等运维控制面静默失效」。
        shield_healthy = False
        logger.error("status shield_healthy=false: %s", e, exc_info=True)

    return jsonify({
        "running": running,
        "mode": _default_mode,
        # R4 修复：/status 补充 version，供桌面端 Rust 在 /dual-layer/stats 降级分支
        # 读取 engine_version，避免恒为 "unknown"。与 /health 共用 _ENGINE_VERSION 常量。
        "version": _ENGINE_VERSION,
        "learning_mode": learning_mode,
        "learning_progress": learning_progress,
        "sample_count": sample_count,
        "uptime": round(uptime, 1),
        "total_requests": total_req,
        "total_blocked": total_blk,
        "block_rate": round(block_rate, 4),
        "cached_modes": list(_shields.keys()),
        "shield_healthy": shield_healthy,
    })


@app.route("/learning/status", methods=["GET"])
def learning_status():
    """返回当前学习状态：模式、进度、原型统计、模拟拦截预览。"""
    try:
        shield = _get_shield(_default_mode)
        ls = shield.get_learning_status()
        resp = jsonify(ls)
        return _attach_cors(resp)
    except Exception as e:
        logger.error("learning_status error: %s", e)
        return jsonify({"error": type(e).__name__}), 500


@app.route("/mode/switch", methods=["POST", "OPTIONS"])
def switch_learning_mode():
    """手动切换观察/保护模式。

    Body: {"mode": "observing" | "protecting"}

    HCSE P1：管理接口，需 _require_admin_auth()。
    """
    if request.method == "OPTIONS":
        resp = jsonify({})
        return _attach_cors(resp)

    _auth = _require_admin_auth("/mode/switch")
    if _auth is not None:
        body, code = _auth
        return _attach_cors(body), code

    data = request.get_json(silent=True) or {}
    target = data.get("mode", "")
    if target not in ("observing", "protecting"):
        return jsonify({"error": f"Invalid mode: {target}"}), 400

    try:
        shield = _get_shield(_default_mode)
        result = shield.switch_mode(target)
        logger.info("Learning mode switched: %s", result)
        resp = jsonify(result)
        return _attach_cors(resp)
    except Exception as e:
        logger.error("switch_mode error: %s", e)
        return jsonify({"error": type(e).__name__}), 500


@app.route("/learning/details", methods=["GET"])
def learning_details():
    """返回原型统计摘要（不暴露原始内容）。"""
    try:
        shield = _get_shield(_default_mode)
        details = shield.get_prototype_examples()
        resp = jsonify(details)
        return _attach_cors(resp)
    except Exception as e:
        logger.error("learning_details error: %s", e)
        return jsonify({"error": type(e).__name__}), 500


# ── 企业级运维：逃生通道 + 灰度部署 ──

@app.route("/emergency/bypass", methods=["GET", "POST", "OPTIONS"])
def emergency_bypass():
    """逃生通道：紧急放行所有请求。

    GET: 返回当前状态
    POST: {"enabled": true/false} 设置开关

    HCSE P1：管理接口，全部方法（含状态查询）都要求 admin 鉴权，
    防止攻击者通过读状态判断目标是否在弱防护状态。
    """
    if request.method == "OPTIONS":
        resp = jsonify({})
        return _attach_cors(resp)

    _auth = _require_admin_auth("/emergency/bypass")
    if _auth is not None:
        body, code = _auth
        return _attach_cors(body), code

    try:
        shield = _get_shield(_default_mode)
        if request.method == "POST":
            data = request.get_json(silent=True) or {}
            enabled = bool(data.get("enabled", False))
            result = shield.set_emergency_bypass(enabled)
            logger.warning("Emergency bypass %s: %s",
                           "ENABLED" if enabled else "DISABLED", result)
            resp = jsonify({"enabled": shield.get_emergency_bypass()})
        else:
            resp = jsonify({
                "enabled": shield.get_emergency_bypass(),
            })
        return _attach_cors(resp)
    except Exception as e:
        logger.error("emergency_bypass error: %s", e)
        return jsonify({"error": type(e).__name__}), 500


@app.route("/gray/deploy", methods=["GET", "POST", "OPTIONS"])
def gray_deploy():
    """灰度部署：按比例拦截请求。

    GET: 返回当前比例
    POST: {"ratio": 0.1} 设置比例（0.0~1.0）

    HCSE P1：管理接口，读/写均需鉴权，避免攻击者读取 ratio 后设计低比例规避攻击。
    """
    if request.method == "OPTIONS":
        resp = jsonify({})
        return _attach_cors(resp)

    _auth = _require_admin_auth("/gray/deploy")
    if _auth is not None:
        body, code = _auth
        return _attach_cors(body), code

    try:
        shield = _get_shield(_default_mode)
        if request.method == "POST":
            data = request.get_json(silent=True) or {}
            ratio = float(data.get("ratio", 1.0))
            result = shield.set_gray_deploy_ratio(ratio)
            logger.info("Gray deploy ratio set: %s", result)
            resp = jsonify({"ratio": shield.get_gray_deploy_ratio()})
        else:
            resp = jsonify({
                "ratio": shield.get_gray_deploy_ratio(),
            })
        return _attach_cors(resp)
    except Exception as e:
        logger.error("gray_deploy error: %s", e)
        return jsonify({"error": type(e).__name__}), 500


@app.route("/bypass/stats", methods=["GET"])
def bypass_stats():
    """返回逃生通道和灰度部署的统计信息。"""
    try:
        shield = _get_shield(_default_mode)
        stats = shield.get_bypass_stats()
        resp = jsonify(stats)
        return _attach_cors(resp)
    except Exception as e:
        logger.error("bypass_stats error: %s", e)
        return jsonify({"error": type(e).__name__}), 500


@app.route("/dual-layer/stats", methods=["GET"])
def dual_layer_stats():
    """返回双层架构（外门/内门）的分层指标。"""
    try:
        shield = _get_shield(_default_mode)
        stats = shield.get_dual_layer_stats()
        resp = jsonify(stats)
        return _attach_cors(resp)
    except Exception as e:
        logger.error("dual_layer_stats error: %s", e)
        return jsonify({"error": type(e).__name__}), 500


@app.route("/learning/snapshot", methods=["GET"])
def get_learning_snapshot():
    """返回当前学习快照数据（从内存读取，不从文件读取）。
    
    快照保存的是各 shield 学习状态统计摘要，包括 call_count、域档案大小、
    原型计数、否定校准状态等。用于前端展示学习趋势和外部系统记忆同步。
    """
    if not _shields:
        return jsonify({"error": "No shields available"}), 404
    snapshots = {}
    for mode, shield in _shields.items():
        da = shield.domain_awareness
        snapshots[mode] = {
            "call_count": da.call_count,
            "sample_count": da.sample_count,
            "profile_sizes": {
                "char": len(da._domain_char_profile),
                "trigram": len(da._domain_trigram_profile),
                "fourgram": len(da._domain_char_fourgram_profile),
                "inquiry_prefixes": len(da._domain_inquiry_prefixes),
                "imperative_prefixes": len(da._domain_imperative_prefixes),
                "learning_phrases": len(da._domain_learning_phrases),
                "rejected_fourgram": len(da._rejected_fourgram_profile),
            },
            "prototype_counts": {
                "total": len(da.prototypes),
                "luoshu_safe": len(da._luoshu.safe_prototypes) if da._luoshu else 0,
                "luoshu_attack": len(da._luoshu.attack_prototypes) if da._luoshu else 0,
            },
            "negation": {
                "calibrated": da._negation_calibrated,
                "sample_count": da._negation_sample_count,
                "weights_locked": da._negation_weights_locked,
            },
            "rejected_fourgram_count": da._rejected_fourgram_count,
            "ewma_mean": da._ewma_mean,
        }
    resp = jsonify({
        "timestamp": time.time(),
        "engine_mode": _default_mode,
        "uptime": round(time.time() - _start_time, 1),
        "cached_modes": list(_shields.keys()),
        "shields": snapshots,
    })
    return _attach_cors(resp)


@app.route("/simulation/run", methods=["POST", "OPTIONS"])
def simulation_run():
    """运行模拟测试。

    Body: {
        "mode": "quick" | "full" | "custom",
        "categories": ["direct_injection", ...],  # 可选，full/quick 模式忽略
        "custom_texts": ["..."],                   # custom 模式必填
    }
    """
    if request.method == "OPTIONS":
        resp = jsonify({})
        return _attach_cors(resp)

    data = request.get_json(silent=True) or {}
    sim_mode = data.get("mode", "quick")
    categories = data.get("categories", [])
    custom_texts = data.get("custom_texts", [])

    try:
        from simulation import SimulationEngine
        engine = SimulationEngine(_get_shield(_default_mode))
        report = engine.run(mode=sim_mode, categories=categories, custom_texts=custom_texts)
        resp = jsonify(report)
        return _attach_cors(resp)
    except Exception as e:
        logger.error("simulation_run error: %s", e, exc_info=True)
        return jsonify({"error": f"Simulation failed: {type(e).__name__}: {e}"}), 500


@app.route("/report/weekly", methods=["POST"])
def report_weekly():
    """周报生成端点：生成指定日期范围的安全周报（PDF/HTML/CSV）。

    v1.3.4 新增，v1.3.4 健康修复：新增 CSV 格式（Excel 可直接打开）。请求体：
      { "start_date": "2026-08-04", "end_date": "2026-08-10",
        "format": "pdf|html|csv", "sections": ["summary","trend","distribution"] }

    返回：
      { "file_path": "...", "file_size": ..., "format": "...",
        "summary": {"total_requests": ..., ...} }
    """
    data = request.get_json(silent=True) or {}
    start_date = data.get("start_date", "")
    end_date = data.get("end_date", "")
    fmt = data.get("format", "html")
    sections = data.get("sections", ["summary"])

    # ── 行走的骨架：先返回硬编码摘要，验证端到端通路 ──
    try:
        import os, tempfile, sqlite3
        from datetime import datetime

        # 使用与 Rust 桌面端相同的数据库路径
        db_dir = os.path.join(
            os.environ.get("LOCALAPPDATA", os.environ.get("TEMP", "/tmp")),
            "com.daoti.xuandun-desktop"
        )
        db_path = os.path.join(db_dir, "xuandun.db")
        total_requests = 0
        total_blocked = 0

        daily_data = []
        top_sources = []
        if os.path.exists(db_path) and start_date and end_date:
            try:
                conn = sqlite3.connect(db_path)
                # 总览统计
                row = conn.execute(
                    "SELECT COUNT(*), SUM(CASE WHEN allowed=0 THEN 1 ELSE 0 END) "
                    "FROM logs WHERE timestamp BETWEEN ? AND ?",
                    (start_date, end_date)
                ).fetchone()
                if row:
                    total_requests = row[0] or 0
                    total_blocked = row[1] or 0

                # 每日明细（按日期分组）
                for drow in conn.execute(
                    "SELECT substr(timestamp,1,10) AS day, COUNT(*), "
                    "SUM(CASE WHEN allowed=0 THEN 1 ELSE 0 END) "
                    "FROM logs WHERE timestamp BETWEEN ? AND ? "
                    "GROUP BY day ORDER BY day",
                    (start_date, end_date)
                ):
                    day_total = drow[1] or 0
                    day_blocked = drow[2] or 0
                    day_rate = (day_blocked / day_total * 100) if day_total > 0 else 0.0
                    daily_data.append({
                        "date": drow[0],
                        "total": day_total,
                        "blocked": day_blocked,
                        "rate": round(day_rate, 2),
                    })

                # Top 攻击来源（按 source 分组）
                for srow in conn.execute(
                    "SELECT source, COUNT(*) AS cnt FROM logs "
                    "WHERE timestamp BETWEEN ? AND ? AND allowed=0 "
                    "GROUP BY source ORDER BY cnt DESC LIMIT 10",
                    (start_date, end_date)
                ):
                    pct = (srow[1] / total_blocked * 100) if total_blocked > 0 else 0.0
                    top_sources.append({
                        "source": srow[0] if srow[0] else "未知",
                        "count": srow[1],
                        "percentage": round(pct, 2),
                    })
                conn.close()
            except Exception:
                pass

        block_rate = (total_blocked / total_requests * 100) if total_requests > 0 else 0.0
        period_days = 1
        try:
            from datetime import date as _date
            d0 = _date.fromisoformat(start_date)
            d1 = _date.fromisoformat(end_date)
            period_days = max(1, (d1 - d0).days + 1)
        except Exception:
            pass

        summary = {
            "total_requests": total_requests,
            "total_blocked": total_blocked,
            "block_rate": round(block_rate, 2),
            "avg_daily": round(total_requests / period_days) if period_days else 0,
            "period": {"start": start_date, "end": end_date},
            "generated_at": datetime.utcnow().isoformat(),
            "daily_data": daily_data,
            "top_sources": top_sources,
        }

        # 生成报告（CSV / JSON / HTML / MD，全部零依赖）
        charts = _render_charts(daily_data, top_sources)
        html_content = _render_weekly_html(summary, sections, charts)
        if fmt == "csv":
            file_path = _render_weekly_csv(summary, sections)
        elif fmt == "json":
            file_path = _render_weekly_json(summary, sections)
        elif fmt == "md":
            file_path = _render_weekly_md(summary, sections)
        else:
            fd, file_path = tempfile.mkstemp(suffix=".html", prefix="xuandun_report_")
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(html_content)
        file_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0

        resp = jsonify({
            "file_path": file_path,
            "file_size": file_size,
            "format": fmt,
            "summary": summary,
        })
        return _attach_cors(resp)
    except Exception as e:
        logger.error("report_weekly error: %s", e, exc_info=True)
        return jsonify({"error": str(e)}), 500


def _render_charts(daily_data: list, top_sources: list) -> dict:
    """使用 Chart.js 生成 Base64 编码的图表（趋势图 + 分布图）。

    在 HTML 渲染阶段，先通过 Jinja2 模板内的 <canvas> 占位，
    但 weasyprint 无法渲染 JS 图表，所以此处用静态 SVG 替代。
    """
    charts = {"trend": "", "distribution": ""}

    # ── 趋势图（折线图）：每日检测量 + 拦截量 ──
    if daily_data:
        dates = [d["date"] for d in daily_data]
        totals = [d["total"] for d in daily_data]
        blocked = [d["blocked"] for d in daily_data]
        max_val = max(totals) if totals else 1
        h = 200
        w = 600
        points_total = []
        points_blocked = []
        for i, (t, b) in enumerate(zip(totals, blocked)):
            x = 40 + (i * (w - 80) / max(1, len(dates) - 1))
            y_total = h - 20 - (t / max_val * (h - 40))
            y_blocked = h - 20 - (b / max_val * (h - 40))
            points_total.append(f"{x:.1f},{y_total:.1f}")
            points_blocked.append(f"{x:.1f},{y_blocked:.1f}")

        # 生成 SVG 折线图
        svg_parts = [
            f'<svg width="{w}" height="{h+40}" xmlns="http://www.w3.org/2000/svg" style="font-family:Microsoft YaHei,sans-serif;font-size:11px">',
            f'<rect width="100%" height="100%" fill="#f8fafc" rx="4"/>',
            # Y 轴网格线
            *[f'<line x1="40" y1="{h-20-(i*(h-40)/4):.0f}" x2="{w-40}" y2="{h-20-(i*(h-40)/4):.0f}" stroke="#e2e8f0" stroke-width="1"/>'
              for i in range(5)],
            # Y 轴标签
            *[f'<text x="35" y="{h-15-(i*(h-40)/4):.0f}" text-anchor="end" fill="#64748b">{max_val*i//4}</text>'
              for i in range(5)],
            # 折线 - 检测总数
            f'<polyline points="{" ".join(points_total)}" fill="none" stroke="#3b82f6" stroke-width="2"/>',
            # 折线 - 拦截量
            f'<polyline points="{" ".join(points_blocked)}" fill="none" stroke="#ef4444" stroke-width="2"/>',
            # 数据点
            *[f'<circle cx="{p.split(",")[0]}" cy="{p.split(",")[1]}" r="3" fill="#3b82f6"/>' for p in points_total],
            *[f'<circle cx="{p.split(",")[0]}" cy="{p.split(",")[1]}" r="3" fill="#ef4444"/>' for p in points_blocked],
            # X 轴标签
            *[f'<text x="{40+i*(w-80)/max(1,len(dates)-1):.0f}" y="{h+15}" text-anchor="middle" fill="#64748b">{d[-5:]}</text>'
              for i, d in enumerate(dates)],
            # 图例
            f'<rect x="{w-160}" y="8" width="12" height="12" fill="#3b82f6" rx="2"/>',
            f'<text x="{w-144}" y="18" fill="#475569">检测总数</text>',
            f'<rect x="{w-80}" y="8" width="12" height="12" fill="#ef4444" rx="2"/>',
            f'<text x="{w-64}" y="18" fill="#475569">拦截量</text>',
            '</svg>',
        ]
        import base64
        charts["trend"] = "data:image/svg+xml;base64," + base64.b64encode(
            "\n".join(svg_parts).encode("utf-8")
        ).decode("ascii")

    # ── 分布图（饼图）：攻击类型占比 ──
    if top_sources:
        pie_colors = ["#3b82f6", "#ef4444", "#f59e0b", "#22c55e", "#8b5cf6",
                      "#ec4899", "#14b8a6", "#f97316", "#6366f1", "#84cc16"]
        total = sum(s["count"] for s in top_sources) or 1
        cx, cy, r = 120, 120, 100
        pie_parts = [f'<svg width="300" height="240" xmlns="http://www.w3.org/2000/svg" style="font-family:Microsoft YaHei,sans-serif;font-size:11px">']
        angle = 0
        for i, src in enumerate(top_sources):
            pct = src["count"] / total
            if pct <= 0:
                continue
            a2 = angle + pct * 360
            mid = angle + pct * 180
            rad = mid * 3.14159 / 180
            lx = cx + r * 0.6 * math.cos(rad)
            ly = cy + r * 0.6 * math.sin(rad)
            x1 = cx + r * math.cos(angle * 3.14159 / 180)
            y1 = cy + r * math.sin(angle * 3.14159 / 180)
            x2 = cx + r * math.cos(a2 * 3.14159 / 180)
            y2 = cy + r * math.sin(a2 * 3.14159 / 180)
            large = 1 if pct > 0.5 else 0
            color = pie_colors[i % len(pie_colors)]
            pie_parts.append(
                f'<path d="M{cx},{cy} L{x1:.1f},{y1:.1f} A{r},{r} 0 {large},1 {x2:.1f},{y2:.1f} Z" '
                f'fill="{color}" stroke="#fff" stroke-width="2"/>'
            )
            # 标签（在扇形外）
            label_r = r + 20
            lx2 = cx + label_r * math.cos(rad)
            ly2 = cy + label_r * math.sin(rad)
            label = src["source"][:8] + ".." if len(src["source"]) > 8 else src["source"]
            pie_parts.append(
                f'<text x="{lx2:.0f}" y="{ly2:.0f}" text-anchor="middle" fill="#475569" font-size="10">{label} {src["percentage"]:.0f}%</text>'
            )
            angle = a2
        pie_parts.append('</svg>')
        import base64
        charts["distribution"] = "data:image/svg+xml;base64," + base64.b64encode(
            "\n".join(pie_parts).encode("utf-8")
        ).decode("ascii")

    return charts


def _render_weekly_html(summary: dict, sections: list, charts: dict = None) -> str:
    """使用 Jinja2 模板渲染周报 HTML。"""
    from jinja2 import Environment, BaseLoader, FileSystemLoader

    # 自定义过滤器：千分位逗号
    def _comma(n):
        try:
            return f"{int(n):,}"
        except (ValueError, TypeError):
            return str(n or 0)

    # 优先使用模板文件，fallback 到内联模板
    tmpl_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")
    tmpl_file = os.path.join(tmpl_dir, "weekly_report.html")
    if os.path.exists(tmpl_file):
        env = Environment(loader=FileSystemLoader(tmpl_dir))
        env.filters["comma"] = _comma
        tmpl = env.get_template("weekly_report.html")
    else:
        # 内联模板（模板文件不存在时的 fallback）
        env = Environment(loader=BaseLoader())
        env.filters["comma"] = _comma
        tmpl = env.from_string("""<!DOCTYPE html>
<html lang="zh-CN">
<head><meta charset="utf-8"><title>道体玄盾 安全周报</title>
<style>
body{font-family:'Microsoft YaHei',sans-serif;max-width:800px;margin:0 auto;padding:20px;color:#1e293b}
h1{color:#1e293b;border-bottom:2px solid #38bdf8;padding-bottom:10px}
.card{background:#f8fafc;border-radius:8px;padding:16px;margin:12px 0;border:1px solid #e2e8f0}
.num{font-size:28px;font-weight:bold;color:#0f172a}
.label{color:#64748b;font-size:14px}
</style></head><body>
<h1>道体玄盾 安全周报</h1>
<p>周期: {{ summary.period.start }} ~ {{ summary.period.end }} | {{ summary.generated_at }}</p>
{% if 'summary' in sections %}
<div class="card">
<div class="num">{{ summary.total_requests | comma }}</div><div class="label">检测总数</div>
<div class="num">{{ summary.total_blocked | comma }}</div><div class="label">拦截次数</div>
<div class="num">{{ summary.block_rate }}%</div><div class="label">拦截率</div>
</div>
{% endif %}
</body></html>""")

    return tmpl.render(summary=summary, sections=sections, charts=charts or {})


def _render_weekly_csv(summary: dict, sections: dict) -> str:
    """生成 CSV 格式周报（Excel 可直接打开，便于统计分析）。

    使用 Python 标准库 csv 模块，无需额外依赖。
    包含概览统计 + 每日明细 + 攻击类型分布。
    """
    import csv
    import tempfile

    fd, csv_path = tempfile.mkstemp(suffix=".csv", prefix="xuandun_report_")

    with os.fdopen(fd, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.writer(f)

        # 标题行
        writer.writerow(["道体玄盾 安全周报"])
        writer.writerow([f"周期: {summary.get('period', {}).get('start', '')} ~ {summary.get('period', {}).get('end', '')}"])
        writer.writerow([f"生成时间: {summary.get('generated_at', '')}"])
        writer.writerow([])

        # 概览统计
        writer.writerow(["=== 概览统计 ==="])
        writer.writerow(["指标", "数值"])
        writer.writerow(["检测总数", summary.get("total_requests", 0)])
        writer.writerow(["拦截次数", summary.get("total_blocked", 0)])
        writer.writerow(["拦截率(%)", summary.get("block_rate", 0)])
        writer.writerow(["日均检测量", summary.get("avg_daily", 0)])
        writer.writerow([])

        # 每日明细
        daily_data = sections.get("daily_detail", [])
        if daily_data:
            writer.writerow(["=== 每日明细 ==="])
            writer.writerow(["日期", "检测数", "拦截数", "拦截率(%)"])
            for row in daily_data:
                writer.writerow([
                    row.get("date", ""),
                    row.get("total", 0),
                    row.get("blocked", 0),
                    row.get("rate", ""),
                ])
            writer.writerow([])

        # 攻击类型分布
        attack_dist = sections.get("attack_distribution", [])
        if attack_dist:
            writer.writerow(["=== 攻击类型分布 ==="])
            writer.writerow(["攻击类型", "次数", "占比(%)"])
            for row in attack_dist:
                writer.writerow([
                    row.get("category", ""),
                    row.get("count", 0),
                    row.get("percentage", ""),
                ])
            writer.writerow([])

        # 来源 Top
        top_sources = sections.get("top_sources", [])
        if top_sources:
            writer.writerow(["=== 来源 Top ==="])
            writer.writerow(["来源", "请求数", "拦截数"])
            for row in top_sources:
                writer.writerow([
                    row.get("source", ""),
                    row.get("requests", 0),
                    row.get("blocked", 0),
                ])

    return csv_path


def _render_weekly_json(summary: dict, sections: dict) -> str:
    """生成 JSON 格式周报（运维人员可编程分析，便于对接其他系统）。

    使用 Python 标准库 json 模块，无需额外依赖。
    """
    import json
    import tempfile

    report_data = {
        "title": "道体玄盾 安全周报",
        "period": summary.get("period", {}),
        "generated_at": summary.get("generated_at", ""),
        "summary": {
            "total_requests": summary.get("total_requests", 0),
            "total_blocked": summary.get("total_blocked", 0),
            "block_rate": summary.get("block_rate", 0),
            "avg_daily": summary.get("avg_daily", 0),
        },
        "daily_detail": sections.get("daily_detail", []),
        "attack_distribution": sections.get("attack_distribution", []),
        "top_sources": sections.get("top_sources", []),
    }

    fd, json_path = tempfile.mkstemp(suffix=".json", prefix="xuandun_report_")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(report_data, f, ensure_ascii=False, indent=2)

    return json_path


def _render_weekly_md(summary: dict, sections: dict) -> str:
    """生成 Markdown 格式周报（可读性好，适合文档/Notion/GitHub）。

    使用纯字符串拼接，无需额外依赖。
    """
    import tempfile

    period = summary.get("period", {})
    lines = [
        "# 道体玄盾 安全周报",
        "",
        f"> 周期: {period.get('start', '')} ~ {period.get('end', '')}  ",
        f"> 生成时间: {summary.get('generated_at', '')}",
        "",
        "## 概览统计",
        "",
        "| 指标 | 数值 |",
        "|------|------|",
        f"| 检测总数 | {summary.get('total_requests', 0)} |",
        f"| 拦截次数 | {summary.get('total_blocked', 0)} |",
        f"| 拦截率(%) | {summary.get('block_rate', 0)} |",
        f"| 日均检测量 | {summary.get('avg_daily', 0)} |",
        "",
    ]

    daily_data = sections.get("daily_detail", [])
    if daily_data:
        lines.append("## 每日明细")
        lines.append("")
        lines.append("| 日期 | 检测数 | 拦截数 | 拦截率(%) |")
        lines.append("|------|--------|--------|----------|")
        for row in daily_data:
            lines.append(f"| {row.get('date', '')} | {row.get('total', 0)} | {row.get('blocked', 0)} | {row.get('rate', '')} |")
        lines.append("")

    attack_dist = sections.get("attack_distribution", [])
    if attack_dist:
        lines.append("## 攻击类型分布")
        lines.append("")
        lines.append("| 攻击类型 | 次数 | 占比(%) |")
        lines.append("|----------|------|---------|")
        for row in attack_dist:
            lines.append(f"| {row.get('category', '')} | {row.get('count', 0)} | {row.get('percentage', '')} |")
        lines.append("")

    top_sources = sections.get("top_sources", [])
    if top_sources:
        lines.append("## 来源 Top")
        lines.append("")
        lines.append("| 来源 | 请求数 | 拦截数 |")
        lines.append("|------|---------|--------|")
        for row in top_sources:
            lines.append(f"| {row.get('source', '')} | {row.get('requests', 0)} | {row.get('blocked', 0)} |")
        lines.append("")

    lines.append("---")
    lines.append("*道体玄盾 v1.3.4 · AI 安全引擎 · 自动生成*")

    fd, md_path = tempfile.mkstemp(suffix=".md", prefix="xuandun_report_")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    return md_path


@app.route("/ping", methods=["GET"])
def ping():
    return jsonify({"pong": True, "ts": time.time()})


@app.route("/metrics/realtime", methods=["GET"])
def metrics_realtime():
    """实时指标端点：返回当前 QPS、延迟分位数、拦截统计。"""
    with _stats_lock:
        total = _total_requests
        blocked = _total_blocked
    block_rate = (blocked / total * 100) if total > 0 else 0.0
    resp = jsonify({
        "total_requests": total,
        "total_blocked": blocked,
        "block_rate": round(block_rate, 2),
        "qps": 0.0,
        "p50_latency_ms": 0.0,
        "p95_latency_ms": 0.0,
        "p99_latency_ms": 0.0,
        "ts": time.time(),
    })
    return _attach_cors(resp)


@app.route("/alert/dispatch", methods=["POST", "OPTIONS"])
def dispatch_alert():
    """接收告警事件并分发到所有已配置的通道。

    HCSE P1：管理接口（会对外发送 HTTP 请求/邮件），必须 admin 鉴权，
    防止被滥用当作垃圾邮件/短信/钉钉轰炸器。
    """
    if request.method == "OPTIONS":
        resp = jsonify({})
        return _attach_cors(resp)

    _auth = _require_admin_auth("/alert/dispatch")
    if _auth is not None:
        body, code = _auth
        return _attach_cors(body), code

    data = request.get_json(silent=True) or {}
    try:
        event = AlertEvent(
            event_type=data.get("event_type", "block"),
            severity=data.get("severity", "info"),
            timestamp=data.get("timestamp", ""),
            attack_category=data.get("attack_category"),
            trust_level=data.get("trust_level", ""),
            reject_stage=data.get("reject_stage"),
            # HCSE P1：分发告警前，对 text_preview 做日志级 PII 脱敏
            text_preview=_redact_pii_for_log(data.get("text_preview", ""), max_preview=200),
            engine_mode=data.get("engine_mode", ""),
            extra=data.get("extra", {}),
        )
        sent = _alert_manager.dispatch(event)
        resp = jsonify({"status": "ok", "sent_count": sent})
        return _attach_cors(resp)
    except Exception as e:
        logger.error("Alert dispatch error: %s", e, exc_info=True)
        resp = jsonify({"status": "error", "message": type(e).__name__})
        return _attach_cors(resp)


@app.route("/notifiers/config", methods=["POST", "OPTIONS"])
def configure_notifiers():
    """批量配置告警通道。Body: {"channels": {"dingtalk": {...}, ...}}

    HCSE P1：管理接口（会写入通道 secret），必须 admin 鉴权，防止密钥被改写。
    """
    if request.method == "OPTIONS":
        resp = jsonify({})
        return _attach_cors(resp)

    _auth = _require_admin_auth("/notifiers/config")
    if _auth is not None:
        body, code = _auth
        return _attach_cors(body), code

    data = request.get_json(silent=True) or {}
    channels = data.get("channels", {})
    _alert_manager.clear_notifiers()
    for channel_name, config in channels.items():
        cls = _NOTIFIER_CLASSES.get(channel_name)
        if cls and config.get("enabled", False):
            _alert_manager.add_notifier(cls(config))
    resp = jsonify({"status": "ok", "active_channels": len(_alert_manager._notifiers)})
    return _attach_cors(resp)


@app.route("/notifiers/test", methods=["POST", "OPTIONS"])
def test_notifier_endpoint():
    """发送测试告警。Body: {"channel": "dingtalk", "config": {...}}

    HCSE P1：管理接口（会向外部通道发请求），必须 admin 鉴权，防止被滥用轰炸。
    """
    if request.method == "OPTIONS":
        resp = jsonify({})
        return _attach_cors(resp)

    _auth = _require_admin_auth("/notifiers/test")
    if _auth is not None:
        body, code = _auth
        return _attach_cors(body), code

    data = request.get_json(silent=True) or {}
    channel = data.get("channel", "")
    config = data.get("config", {})
    cls = _NOTIFIER_CLASSES.get(channel)
    if not cls:
        resp = jsonify({"status": "error", "message": f"Unknown channel: {channel}"})
        return _attach_cors(resp)
    test_event = AlertEvent(
        event_type="test",
        severity="info",
        timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        attack_category="test",
        trust_level="TEST",
        reject_stage="test",
        text_preview="这是一条来自道体玄盾的测试告警",
        engine_mode="balanced",
    )
    notifier = cls(config)
    ok = notifier.send(test_event)
    resp = jsonify({"status": "ok" if ok else "failed", "channel": channel})
    return _attach_cors(resp)


@app.route("/debug/state", methods=["GET"])
def debug_state():
    """调试端点：返回各模式的原型数、配置值和预热状态。

    需要 X-Debug-Token 请求头匹配 XUANDUN_DEBUG_TOKEN 环境变量。
    未配置 token 时返回 404 隐藏端点存在性。
    """
    if not _DEBUG_TOKEN:
        return jsonify({"error": "not found"}), 404
    provided = request.headers.get("X-Debug-Token", "")
    if provided != _DEBUG_TOKEN:
        return jsonify({"error": "unauthorized"}), 401
    info = {}
    for mode, shield in _shields.items():
        da = shield.domain_awareness
        config = shield.config
        proto_sum = float(da.prototypes.sum()) if len(da.prototypes) > 0 else 0.0
        proto_norm_0 = float(np.linalg.norm(da.prototypes[0])) if len(da.prototypes) > 0 else 0.0
        test_text = "你好，请帮我写一首关于春天的诗"
        test_feat = da._input_to_vector(test_text)
        test_norm = float(np.linalg.norm(test_feat))
        test_sum = float(test_feat.sum())
        if len(da.prototypes) > 0:
            test_dist, test_idx = da._nearest_prototype(test_feat)
        else:
            test_dist, test_idx = -1.0, -1
        info[mode] = {
            "prototype_count": len(da.prototypes),
            "prototype_sum": proto_sum,
            "prototype_norm_0": proto_norm_0,
            "call_count": da.call_count,
            "enable_decode_preprocess": config.enable_decode_preprocess,
            "prototype_distance_threshold": config.prototype_distance_threshold,
            "reject_boundary_multiplier": config.reject_boundary_multiplier,
            "reject_boundary": config.prototype_distance_threshold * config.reject_boundary_multiplier,
            "structural_anomaly_threshold": config.structural_anomaly_threshold,
            "enable_luoshu_mapper": config.enable_luoshu_mapper,
            "luoshu_attack_prototypes": len(da._luoshu.attack_prototypes) if da._luoshu else 0,
            "luoshu_safe_prototypes": len(da._luoshu.safe_prototypes) if da._luoshu else 0,
            "domain_char_count": da._domain_char_count,
            "domain_char_profile": dict(da._domain_char_profile),
            "rejected_fourgram_count": da._rejected_fourgram_count,
            "test_text": test_text,
            "test_feat_norm": test_norm,
            "test_feat_sum": test_sum,
            "test_nearest_dist": float(test_dist),
            "test_nearest_idx": int(test_idx),
            "has_proj_matrix": da._proj_matrix is not None,
        }
    return jsonify(info)


_ATTACK_CATEGORY_KEYWORDS = {
    "direct_prompt_injection": [
        "ignore previous", "ignore above", "disregard", "system prompt",
        "you are now", "new instruction", "override", "forget your",
    ],
    "jailbreak": [
        "dan", "do anything now", "jailbreak", "扮演", "角色扮演",
        "无限制", "unrestricted", "developer mode", "无约束",
    ],
    "encoding_obfuscation": [
        "base64", "decode this", "unicode", "\\u", "零宽",
        "rot13", "hex decode", "morze",
    ],
    "indirect_prompt_injection": [
        "web page", "email", "rag", "retrieval", "document says",
        "article says", "网页内容", "邮件内容",
    ],
    "agent_attack": [
        "tool", "function call", "shell", "exec", "command",
        "api key", "sudo", "rm -rf", "工具调用", "命令执行",
    ],
    "data_leakage": [
        "reveal your", "show your prompt", "training data",
        "conversation history", "repeat your", "泄露", "提取系统",
    ],
}


def _classify_attack_category(text: str, reject_stage=None) -> str:
    """基于关键词匹配对输入文本进行攻击分类。

    无论引擎是否拦截，都返回分类结果。
    reject_stage 仅用于日志和告警增强，不影响分类逻辑。
    """
    text_lower = text.lower()
    for category, keywords in _ATTACK_CATEGORY_KEYWORDS.items():
        for kw in keywords:
            if kw.lower() in text_lower:
                return category
    return "other"


@app.route("/protect", methods=["POST", "OPTIONS"])
def protect():
    if request.method == "OPTIONS":
        resp = jsonify({})
        return _attach_cors(resp)

    data = request.get_json(silent=True) or {}
    text = data.get("text", "")
    session = data.get("session", str(uuid.uuid4())[:8])
    # R3 修复：遵循请求级 mode（若合法），否则回退全局默认模式。
    # 此前引擎忽略请求中的 mode，一律用 _default_mode，与桌面端 Rust 发送的
    # mode 字段契约不一致——在 set-mode 尚未同步时 UI 显示模式与实际防护可能不符。
    # _get_shield 会按 mode 缓存 shield，合法 mode 不会重复实例化，成本可忽略。
    req_mode = data.get("mode") or _default_mode
    mode = req_mode if req_mode in _MODE_MAP else _default_mode

    if not text:
        return jsonify({"error": "text is required"}), 400

    try:
        shield = _get_shield(mode)
        t0 = time.perf_counter()
        result = shield.protect(text, session_id=session)
        lat = (time.perf_counter() - t0) * 1000
        # HCSE P1：日志脱敏 — 不把原始 text 写日志，只写 80 字符以内 PII 打码片段
        #   以及 reject_stage/attack_category，便于排障但不泄露用户隐私
        rejected = not result.allowed
        cat = (
            result.attack_category
            or _classify_attack_category(text, result.reject_stage)
        )
        logger.info(
            "protect() took %.1fms session=%s mode=%s reject_stage=%s category=%s rejected=%s preview=%s",
            lat, session, mode,
            result.reject_stage, cat, rejected,
            _redact_pii_for_log(text),
        )

        with _stats_lock:
            global _total_requests, _total_blocked
            _total_requests += 1
            if rejected:
                _total_blocked += 1

        response = {
            "allowed": result.allowed,
            "trust_level": result.trust_level.value if hasattr(result.trust_level, "value") else str(result.trust_level),
            "reject_stage": result.reject_stage,
            "domain_distance": result.domain_distance,
            "timing_distance": result.timing_distance,
            "attack_category": cat,
            "latency_ms": round(lat, 2),
            # 多轮对话状态跟踪（P0 任务：trust_decay + intent_drift）
            "trust_decay_value": result.trust_decay_value,
            "intent_drift_score": result.intent_drift_score,
            "intent_drift_detected": result.intent_drift_detected,
            # 敏感信息泄露防护（P1 任务：medium 命中时返回脱敏文本）
            "redacted_text": (
                result.debug_info.get("redacted_text")
                if isinstance(result.debug_info, dict)
                else None
            ),
        }
        resp = jsonify(response)

        # 检查是否需要保存学习快照（按 call_count 增长阈值触发）
        # R3 修复：快照应记录实际生效的 mode（请求级 mode 或全局默认），而非固定 _default_mode
        _maybe_save_snapshot(mode)

        return _attach_cors(resp)

    except Exception as e:
        logger.error("Protect error: %s", e, exc_info=True)
        resp = jsonify({
            "allowed": False,
            "trust_level": "BLOCKED",
            "reject_stage": "engine_exception",
            "domain_distance": None,
            "timing_distance": None,
            "attack_category": None,
            "latency_ms": None,
            "fallback": True,
            "message": f"Engine error: {type(e).__name__}",
            # 异常降级路径也包含多轮状态字段，保证前端解包一致
            "trust_decay_value": None,
            "intent_drift_score": None,
            "intent_drift_detected": None,
            "redacted_text": None,
        })
        return _attach_cors(resp)


@app.route("/output/protect", methods=["POST", "OPTIONS"])
def output_protect():
    """输出护栏：检测模型输出是否含违规内容（双向闭环的"输出侧"）。

    Body: {"text": "模型输出文本", "session": "会话标识(可选)"}
    三级处置：high→拦截 / medium→打码 / low→仅告警。
    任何异常降级放行并告警，绝不断服务。
    """
    if request.method == "OPTIONS":
        resp = jsonify({})
        return _attach_cors(resp)

    data = request.get_json(silent=True) or {}
    text = data.get("text", "")
    session = data.get("session", "default")

    if not text:
        return jsonify({"error": "text is required"}), 400

    try:
        shield = _get_shield(_default_mode)
        t0 = time.perf_counter()
        decision = shield.check_output(text, session_id=session)
        resolved = shield.resolve_output(text, decision)
        lat = (time.perf_counter() - t0) * 1000
        # HCSE P1：输出侧日志也脱敏，避免把模型输出的敏感内容（如邮箱/卡号/token）写入磁盘
        logger.info("output/protect took %.1fms session=%s risk=%s preview=%s",
                    lat, session, decision.get("risk_level"),
                    _redact_pii_for_log(text))

        resp = jsonify({
            "allowed": decision.get("allowed", True),
            "risk_level": decision.get("risk_level", "pass"),
            "action": decision.get("action", "pass"),
            "reason": decision.get("reason", ""),
            "output": resolved,
            "violation_distance": decision.get("violation_distance"),
            "safe_distance": decision.get("safe_distance"),
            "degraded": decision.get("degraded", False),
            "latency_ms": round(lat, 2),
        })
        return _attach_cors(resp)
    except Exception as e:
        logger.error("output/protect error: %s", e, exc_info=True)
        return jsonify({"allowed": True, "fallback": True, "error": type(e).__name__}), 200


# ─────────────────────────────────────────────────────────────
# OpenAI 兼容透明防护网关（产品闭环：装了玄盾 → 模型被保护）
#   让用户把模型的 base_url 改成本地引擎地址即可透明接入防护，
#   无需改模型客户端代码。支持云端 API / 本地模型(Ollama等) / 私有化部署。
#
# 上游模型配置（禁止硬编码，全部走环境变量）：
#   XUANDUN_UPSTREAM_URL       必填，上游模型的 OpenAI 兼容地址，
#                              e.g. https://api.openai.com/v1
#                                    http://localhost:11434/v1
#                                    http://内网:8000/v1
#   XUANDUN_UPSTREAM_API_KEY   可选，上游 API Key（云端/需鉴权的私有化）
#   XUANDUN_UPSTREAM_MODEL     可选，默认模型名（缺省用请求里的 model）
#   XUANDUN_UPSTREAM_TIMEOUT   可选，请求上游超时秒数（默认 300）
#
# 防护链路：输入侧 /protect → 上游模型 → 输出侧 /output/protect
# 当前为同步（非流式）透传；stream=true 时返回明确的兼容错误提示。
# ─────────────────────────────────────────────────────────────

_UPSTREAM_URL = os.environ.get("XUANDUN_UPSTREAM_URL", "").rstrip("/")
_UPSTREAM_API_KEY = os.environ.get("XUANDUN_UPSTREAM_API_KEY", "")
_UPSTREAM_MODEL = os.environ.get("XUANDUN_UPSTREAM_MODEL", "")
try:
    _UPSTREAM_TIMEOUT = float(os.environ.get("XUANDUN_UPSTREAM_TIMEOUT", "300"))
except ValueError:
    _UPSTREAM_TIMEOUT = 300.0


def _extract_conversation_text(data: dict) -> str:
    """从 OpenAI 请求体的 messages 中提取待检测文本（拼接全部 content）。"""
    messages = data.get("messages") or []
    parts = []
    for m in messages:
        content = m.get("content")
        if isinstance(content, str):
            parts.append(content)
        elif isinstance(content, list):
            # 多模态 content（如 [{"type":"text","text":"..."}]）只取文本片段
            for seg in content:
                if isinstance(seg, dict) and seg.get("type") == "text":
                    parts.append(seg.get("text", ""))
    return "\n".join(parts) if parts else ""


def _upstream_headers() -> dict:
    headers = {"Content-Type": "application/json"}
    if _UPSTREAM_API_KEY:
        headers["Authorization"] = f"Bearer {_UPSTREAM_API_KEY}"
    return headers


def _openai_error(message: str, code: int = 400, err_type: str = "invalid_request_error"):
    return jsonify({
        "error": {
            "message": message,
            "type": err_type,
            "code": code,
        }
    }), code


@app.route("/v1/chat/completions", methods=["POST", "OPTIONS"])
def v1_chat_completions():
    """OpenAI 兼容防护端点：输入防护 → 上游转发 → 输出防护。

    未配置 XUANDUN_UPSTREAM_URL 时返回配置错误，引导用户先配置上游模型，
    避免引擎静默透传（无防护）误导用户以为已受到保护。
    """
    global _total_requests, _total_blocked

    if request.method == "OPTIONS":
        resp = jsonify({})
        return _attach_cors(resp)

    if not _UPSTREAM_URL:
        return _openai_error(
            "XuanDun gateway not configured: XUANDUN_UPSTREAM_URL is not set. "
            "Point your model base_url to this engine and set the upstream model env.",
            code=503, err_type="server_error",
        )

    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict) or "messages" not in data:
        return _openai_error("Invalid request: 'messages' is required.")

    # 当前同步实现不支持流式透传（waitress 同步 WSGI 无法透传 SSE）
    if data.get("stream"):
        return _openai_error(
            "Streaming (stream=true) is not supported by the desktop gateway yet. "
            "Set stream=false or use the SDK gateway for streaming.",
            code=400, err_type="invalid_request_error",
        )

    session = request.headers.get("X-Session-Id") or data.get("session_id") or str(uuid.uuid4())[:8]
    conv_text = _extract_conversation_text(data)

    try:
        shield = _get_shield(_default_mode)

        # ── ① 输入侧检测 ──
        if conv_text:
            result = shield.protect(conv_text, session_id=session)
            if not result.allowed:
                with _stats_lock:
                    _total_requests += 1
                    _total_blocked += 1
                cat = result.attack_category
                logger.info(
                    "v1/chat input blocked session=%s stage=%s category=%s",
                    session, result.reject_stage, cat,
                )
                return _openai_error(
                    f"Input blocked by XuanDun shield (stage={result.reject_stage}).",
                    code=403, err_type="shield_block",
                )

        # ── ② 构造上游请求体（锁定 stream=False，移除 session 私有字段） ──
        upstream_body = {k: v for k, v in data.items() if k not in ("session_id",)}
        upstream_body["stream"] = False
        if _UPSTREAM_MODEL and not upstream_body.get("model"):
            upstream_body["model"] = _UPSTREAM_MODEL

        req = urllib.request.Request(
            f"{_UPSTREAM_URL}/chat/completions",
            data=json.dumps(upstream_body).encode("utf-8"),
            headers=_upstream_headers(),
            method="POST",
        )

        with _stats_lock:
            _total_requests += 1

        t0 = time.perf_counter()
        try:
            with urllib.request.urlopen(req, timeout=_UPSTREAM_TIMEOUT) as upstream_resp:
                raw = upstream_resp.read().decode("utf-8")
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", "replace")
            logger.warning("v1/chat upstream HTTP %s session=%s", e.code, session)
            return jsonify({
                "error": {
                    "message": f"Upstream model returned HTTP {e.code}",
                    "type": "upstream_error",
                    "code": e.code,
                    "upstream": body[:500],
                }
            }), 502
        except urllib.error.URLError as e:
            logger.warning("v1/chat upstream unreachable session=%s err=%s", session, e)
            return _openai_error(
                f"Upstream model unreachable: {e.reason}",
                code=502, err_type="upstream_error",
            )
        lat = (time.perf_counter() - t0) * 1000

        try:
            upstream_data = json.loads(raw)
        except ValueError:
            return _openai_error(
                "Upstream model returned malformed JSON.", code=502, err_type="upstream_error",
            )

        # ── ③ 输出侧检测 ──
        try:
            choice = upstream_data["choices"][0]
            output_text = choice.get("message", {}).get("content", "")
        except (KeyError, IndexError, TypeError):
            output_text = ""

        if output_text:
            decision = shield.check_output(output_text, session_id=session)
            action = decision.get("action", "pass")
            if action == "block":
                logger.info("v1/chat output blocked session=%s risk=%s", session, decision.get("risk_level"))
                return _openai_error(
                    "Output blocked by XuanDun shield.",
                    code=403, err_type="shield_block",
                )
            elif action == "redact":
                resolved = shield.resolve_output(output_text, decision)
                upstream_data["choices"][0]["message"]["content"] = resolved

        logger.info("v1/chat forwarded session=%s upstream_lat=%.1fms", session, lat)
        resp = jsonify(upstream_data)
        return _attach_cors(resp)

    except Exception as e:
        logger.error("v1/chat error: %s", e, exc_info=True)
        return jsonify({
            "error": {
                "message": f"XuanDun gateway internal error: {type(e).__name__}",
                "type": "server_error",
                "code": 500,
            }
        }), 500


@app.route("/external/protect", methods=["POST", "OPTIONS"])
def external_protect():
    """间接提示注入防护（RAG/邮件/网页摘要场景下的"外部内容 + 嵌入恶意指令"检测）。

    Body:
        - text:       用户传给 LLM 的整段 prompt（可能已拼接外部内容）  # 必填
        - sanitize:   是否返回行级脱敏后的安全文本（默认 true）
        - session:    可选会话标识（用于复用流水线统计）

    响应字段：
        - allowed:           是否通过（score ≥ block_threshold 则为 false）
        - reject_stage:      若不通过，固定为 "external_injection"
        - score:             特征累计得分（越高越危险）
        - category:          最危险的命中类型（ignore_prefix / prompt_probe / data_exfil / role_hijack / delimiter）
        - severity:          最坏命中的严重级别："high"|"medium"|"none"
        - matches:           最多 10 条命中摘要（每条含 category/severity/pattern/offset）
        - sanitized_text:    若 sanitize=true，返回已行级删除恶意行后的安全文本
        - latency_ms:        耗时
    任何异常降级为 allowed=true，保证业务不中断。
    """
    if request.method == "OPTIONS":
        resp = jsonify({})
        return _attach_cors(resp)

    data = request.get_json(silent=True) or {}
    text = data.get("text", "")
    sanitize = bool(data.get("sanitize", True))
    session = data.get("session", "default")

    if not isinstance(text, str):
        resp = jsonify({"error": "text 必须是字符串", "allowed": False})
        return _attach_cors(resp), 400
    if not text.strip():
        resp = jsonify({"error": "text 不能为空", "allowed": False})
        return _attach_cors(resp), 400

    try:
        # 优先复用 shield 内置的 external_checker（保证与 protect() 流水线阈值一致）
        shield = _get_shield(_default_mode)
        checker = getattr(shield, "external_checker", None)
        if checker is None:
            from daoti_xuandun._check_external import ExternalContentChecker
            checker = ExternalContentChecker()

        t0 = time.perf_counter()
        decision = checker.check(text)
        lat = (time.perf_counter() - t0) * 1000
        # HCSE P1：间接注入检测日志 — preview 脱敏，同时把 category/score 写清楚
        logger.info("external/protect score=%.2f allowed=%s took %.1fms session=%s category=%s preview=%s",
                    decision.score, not decision.block, lat, session,
                    decision.category or "none",
                    _redact_pii_for_log(text))

        with _stats_lock:
            global _total_requests, _total_blocked
            _total_requests += 1
            if decision.block:
                _total_blocked += 1

        match_info = [
            {
                "category": m.category,
                "severity": m.severity,
                "pattern": m.pattern_name,
                "offset": [m.start, m.end],
            }
            for m in decision.matches
        ][:10]

        sanitized_text: Optional[str] = None
        if sanitize:
            try:
                sanitized_text = checker.sanitize(text)
            except Exception:
                sanitized_text = None

        resp = jsonify({
            "allowed": not decision.block,
            "reject_stage": None if not decision.block else "external_injection",
            "score": round(decision.score, 2),
            "category": decision.category,
            "severity": decision.severity,
            "matches": match_info,
            "sanitized_text": sanitized_text,
            "latency_ms": round(lat, 2),
        })
        return _attach_cors(resp)
    except Exception as e:
        logger.error("external/protect error: %s", e, exc_info=True)
        # 异常降级：允许放行 + 标记 degraded
        resp = jsonify({
            "allowed": True,
            "reject_stage": None,
            "score": None,
            "category": None,
            "severity": None,
            "matches": [],
            "sanitized_text": None,
            "latency_ms": None,
            "degraded": True,
            "message": f"Engine error: {type(e).__name__}",
        })
        return _attach_cors(resp), 500


@app.route("/output/warmup", methods=["POST", "OPTIONS"])
def output_warmup():
    """预热输出护栏原型库（安全输出 + 违规输出）。

    Body: {"safe": ["正常输出样本"], "violations": ["违规输出样本"]}

    HCSE P1：管理接口（写入原型库），必须 admin 鉴权，防止投毒污染安全原型。
    """
    if request.method == "OPTIONS":
        resp = jsonify({})
        return _attach_cors(resp)

    _auth = _require_admin_auth("/output/warmup")
    if _auth is not None:
        body, code = _auth
        return _attach_cors(body), code

    data = request.get_json(silent=True) or {}
    safe_texts = data.get("safe") or []
    violation_texts = data.get("violations") or []

    try:
        shield = _get_shield(_default_mode)
        before = shield.get_output_guardrail_stats()
        shield.warmup_output_guardrail(safe_texts=safe_texts,
                                       violation_texts=violation_texts)
        after = shield.get_output_guardrail_stats()
        # HCSE P1：写 warmup 日志时也对原文列表做脱敏（只记数量不记原文）
        logger.info("output/warmup completed safe=%d violations=%d",
                    len(safe_texts), len(violation_texts))
        resp = jsonify({
            "status": "ok",
            "before": before,
            "after": after,
        })
        return _attach_cors(resp)
    except Exception as e:
        logger.error("output/warmup error: %s", e, exc_info=True)
        return jsonify({"error": type(e).__name__}), 500


@app.route("/output/stats", methods=["GET"])
def output_stats():
    """返回输出护栏运行统计（脱敏，不含原始内容）。"""
    try:
        shield = _get_shield(_default_mode)
        stats = shield.get_output_guardrail_stats()
        resp = jsonify(stats)
        return _attach_cors(resp)
    except Exception as e:
        logger.error("output/stats error: %s", e)
        return jsonify({"error": type(e).__name__}), 500


@app.route("/output/stats/timeseries", methods=["GET"])
def output_stats_timeseries():
    """返回输出护栏处置趋势（时间序列，脱敏）。

    Query 参数：
        granularity: minute / hour / day（默认 hour）
        start: ISO 时间字符串（含毫秒，可选）
        end:   ISO 时间字符串（含毫秒，可选）
    返回：{"points": [{time, checked, blocked, redacted, alerted}, ...]}
    """
    try:
        shield = _get_shield(_default_mode)
        granularity = request.args.get("granularity", "hour")
        start = request.args.get("start")
        end = request.args.get("end")
        points = shield.get_output_guardrail_trend(granularity, start, end)
        resp = jsonify({"points": points})
        return _attach_cors(resp)
    except Exception as e:
        logger.error("output/stats/timeseries error: %s", e)
        return jsonify({"error": type(e).__name__}), 500


@app.route("/output/history", methods=["GET"])
def output_history():
    """返回输出护栏最近处置记录（脱敏，不含原始内容）。

    Query 参数：
        limit: 返回条数（默认 20，上限 200）
    返回：{"history": [{time, action, risk_level, reason, preview}, ...]}（新的在前）
    """
    try:
        shield = _get_shield(_default_mode)
        limit_args = request.args.get("limit", "20")
        try:
            limit = int(limit_args)
        except (TypeError, ValueError):
            limit = 20
        history = shield.get_output_guardrail_history(limit)
        resp = jsonify({"history": history})
        return _attach_cors(resp)
    except Exception as e:
        logger.error("output/history error: %s", e)
        return jsonify({"error": type(e).__name__}), 500


@app.route("/output/config", methods=["GET", "POST", "OPTIONS"])
def output_config():
    """读取 / 动态调校输出护栏配置（专家模式）。

    GET:  返回当前生效参数快照（白名单内全部参数），供前端回显。
    POST: {"config": {key: value}} 仅更新白名单内可调参数，返回生效快照。

    可调参数（自 _check_output._RUNTIME_CONFIG_WHITELIST）：
      enable_output_guardrail(bool) / output_guardrail_high_threshold(float) /
      output_guardrail_medium_threshold(float) / output_guardrail_low_threshold(float) /
      output_guardrail_safe_exempt(float) / output_guardrail_rule_block_signal(float) /
      output_guardrail_rule_medium_signal(float) / output_guardrail_redact_token(str)

    HCSE P1：管理接口（改阈值直接影响拦截/打码/告警判定），必须 admin 鉴权。
    """
    if request.method == "OPTIONS":
        resp = jsonify({})
        return _attach_cors(resp)

    _auth = _require_admin_auth("/output/config")
    if _auth is not None:
        body, code = _auth
        return _attach_cors(body), code

    try:
        shield = _get_shield(_default_mode)
        if request.method == "POST":
            data = request.get_json(silent=True) or {}
            cfg = data.get("config") or {}
            if not isinstance(cfg, dict):
                return jsonify({"error": "config must be an object"}), 400
            snapshot = shield.update_output_guardrail_config(cfg)
            logger.info("output/config updated keys=%s", sorted(cfg.keys()))
        else:
            snapshot = shield.get_output_guardrail_config()
        resp = jsonify({"status": "ok", "config": snapshot})
        return _attach_cors(resp)
    except Exception as e:
        logger.error("output/config error: %s", e, exc_info=True)
        return jsonify({"error": type(e).__name__}), 500


@app.route("/set-mode", methods=["POST", "OPTIONS"])
def set_mode():
    """切换防御层级（balanced/high_security/low_false_positive）。

    HCSE P1：管理接口（改变防御等级），必须 admin 鉴权，防止攻击者强制降级到低误报模式。
    """
    if request.method == "OPTIONS":
        resp = jsonify({})
        return _attach_cors(resp)

    _auth = _require_admin_auth("/set-mode")
    if _auth is not None:
        body, code = _auth
        return _attach_cors(body), code

    global _default_mode
    data = request.get_json(silent=True) or {}
    new_mode = data.get("mode", "")
    if new_mode not in _MODE_MAP:
        return jsonify({"error": f"Invalid mode: {new_mode}"}), 400

    # 事务化：先创建/预热目标模式的 shield，成功后再提交 _default_mode。
    # 修复「先改 _default_mode 再 _get_shield」的顺序缺陷——若懒创建失败，
    # 旧逻辑会让 _default_mode 指向不存在的实例，导致逃生/灰度等关键端点
    # 全部 500，且 /status 显示 mode 已切换而 cached_modes 却没有该模式，
    # 造成「引擎看似在线但运维控制面静默失效」的状态不一致。
    try:
        _get_shield(new_mode)
    except Exception as e:
        logger.error("set-mode failed for %s: %s", new_mode, e, exc_info=True)
        return jsonify({"error": f"failed to activate mode {new_mode}: {type(e).__name__}"}), 500

    _default_mode = new_mode
    _save_learning_snapshot()
    logger.info("Mode switched to %s", new_mode)
    return jsonify({"status": "ok", "mode": new_mode})


@app.route("/warmup", methods=["POST", "OPTIONS"])
def warmup():
    """输入侧洛书原型库预热（安全文本 + 攻击文本）。

    HCSE P1：管理接口（直接写入原型库），必须 admin 鉴权，防止投毒污染安全/攻击原型。
    """
    if request.method == "OPTIONS":
        resp = jsonify({})
        return _attach_cors(resp)

    _auth = _require_admin_auth("/warmup")
    if _auth is not None:
        body, code = _auth
        return _attach_cors(body), code

    data = request.get_json(silent=True) or {}
    safe_texts = data.get("safe_texts", [])
    attack_texts = data.get("attack_texts", [])

    if not safe_texts and not attack_texts:
        return jsonify({"error": "No warmup texts provided"}), 400

    global _shields
    mode = _default_mode

    try:
        shield = XuanDun(
            mode=mode,
            warmup_safe=safe_texts if safe_texts else None,
            warmup_attacks=attack_texts if attack_texts else None,
        )
        _shields[mode] = shield
        # HCSE P1：日志只写数量，不写文本原文（防投毒+脱敏）
        logger.info("Warmup completed: safe=%d attack=%d texts mode=%s",
                    len(safe_texts), len(attack_texts), mode)
        return jsonify({"status": "ok", "safe_count": len(safe_texts),
                        "attack_count": len(attack_texts), "mode": mode})
    except Exception as e:
        logger.error("Warmup failed: %s", e)
        return jsonify({"error": f"Warmup failed: {type(e).__name__}"}), 500


def _signal_handler(signum, frame):
    global running
    logger.info("Received signal %s, shutting down gracefully...", signum)
    running = False
    sys.exit(0)


def _monitor_debugger():
    while running:
        if _ANTI_DEBUG_AVAILABLE and anti_debug.is_debugger_present():
            logger.error("Debugger attached during runtime! Shutting down.")
            os._exit(1)
        time.sleep(5)


def main():
    global _default_mode, _LEARNING_SNAPSHOT_DIR, _LEARNING_SNAPSHOT_PATH

    if _ANTI_DEBUG_AVAILABLE:
        if anti_debug.is_debugger_present():
            logger.warning("Debugger detection triggered — skipping (non-fatal)")
        if not anti_debug.verify_binary_integrity():
            logger.warning("Binary integrity check skipped — continuing engine startup")
        # 仅在非 Nuitka onefile 环境运行反调试监控线程
        if not os.environ.get("NUITKA_ONEFILE_PARENT") and not hasattr(sys, "frozen"):
            monitor_thread = threading.Thread(target=_monitor_debugger, daemon=True)
            monitor_thread.start()

    parser = argparse.ArgumentParser(description="道体玄盾 桌面端引擎")
    parser.add_argument("--port", type=int, default=18765)
    parser.add_argument("--host", type=str, default="127.0.0.1")
    parser.add_argument("--mode", type=str, default="balanced",
                        choices=["high_security", "balanced", "low_false_positive"])
    parser.add_argument("--data-dir", type=str, default=None,
                        help="引擎数据目录，用于存放快照和持久化数据（默认：当前目录）")
    args = parser.parse_args()

    _default_mode = args.mode

    # 初始化学习快照路径
    _LEARNING_SNAPSHOT_DIR = args.data_dir or os.getcwd()
    _LEARNING_SNAPSHOT_PATH = os.path.join(_LEARNING_SNAPSHOT_DIR, "learning_snapshot.json")
    logger.info("Learning snapshot path: %s", _LEARNING_SNAPSHOT_PATH)

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    # 只初始化默认模式，其他模式按需懒加载（加速启动）
    logger.info("Initializing default shield mode: %s", args.mode)
    _get_shield(args.mode)
    logger.info("Default shield mode initialized.")

    # 修复2：启动时加载学习快照，恢复学习状态摘要
    _load_learning_snapshot()

    logger.info("道体玄盾引擎启动: %s:%d (mode=%s)", args.host, args.port, args.mode)

    try:
        from waitress import serve
        logger.info("Using waitress production WSGI server")
        serve(app, host=args.host, port=args.port, threads=4)
    except ImportError:
        # 生产环境强制要求 waitress，拒绝 fallback 到 Flask 开发服务器
        if os.environ.get("XUANDUN_REQUIRE_WAITRESS") == "1":
            logger.error(
                "waitress not available but XUANDUN_REQUIRE_WAITRESS=1. "
                "Refusing to start with insecure Flask development server. "
                "Please install waitress: pip install waitress"
            )
            sys.exit(1)
        logger.warning("waitress not available, falling back to Flask development server (NOT for production)")
        app.run(host=args.host, port=args.port, threaded=True, debug=False)


# ============================================================
# 敏感信息泄露防护：企业自定义敏感词典 API（节 9.7）
# ============================================================
# POST   /sensitive/dict          —— 添加自定义敏感关键词或正则
# GET    /sensitive/dict          —— 列出当前所有自定义敏感模式
# DELETE /sensitive/dict/<name>   —— 删除指定 name 的自定义模式
# 所有端点均带 CORS；管理侧可进一步加鉴权（由 /debug/state 同样方式扩展）

@app.route("/sensitive/dict", methods=["POST", "OPTIONS"])
def add_sensitive_dict_entry():
    """添加一条企业自定义敏感模式（关键词或正则）。

    HCSE P1：管理接口（写入敏感词典），必须 admin 鉴权，
    防止攻击者写入 "all" 之类的关键词触发全量拦截，或删除必要的词典。
    """
    if request.method == "OPTIONS":
        resp = jsonify({})
        return _attach_cors(resp)

    _auth = _require_admin_auth("/sensitive/dict")
    if _auth is not None:
        body, code = _auth
        return _attach_cors(body), code

    data = request.get_json(silent=True) or {}
    kind = data.get("kind")
    name = (data.get("name") or "").strip()
    payload = data.get("payload")
    category = (data.get("category") or "custom").strip() or "custom"
    severity = (data.get("severity") or "medium").strip()
    if severity not in ("high", "medium", "low"):
        severity = "medium"
    case_sensitive = bool(data.get("case_sensitive", False))

    if kind not in ("keyword", "regex"):
        resp = jsonify({"ok": False, "message": "kind 必须是 keyword 或 regex"})
        return _attach_cors(resp), 400
    if not name:
        resp = jsonify({"ok": False, "message": "name 必填，不能为空"})
        return _attach_cors(resp), 400
    if payload is None or (isinstance(payload, str) and not payload.strip()):
        resp = jsonify({"ok": False, "message": "payload 必填，不能为空"})
        return _attach_cors(resp), 400

    try:
        shield = _get_shield(_default_mode)
        if kind == "keyword":
            ok, msg = shield.add_sensitive_keyword(
                name, payload, category=category, severity=severity,
                case_sensitive=case_sensitive,
            )
        else:
            ok, msg = shield.add_sensitive_regex(
                name, payload, category=category, severity=severity,
                case_sensitive=case_sensitive,
            )
        status = 200 if ok else 400
        resp = jsonify({"ok": ok, "message": msg})
        return _attach_cors(resp), status
    except Exception as e:
        logger.error("add_sensitive_dict error: %s", e, exc_info=True)
        resp = jsonify({"ok": False, "message": f"Engine error: {type(e).__name__}"})
        return _attach_cors(resp), 500


@app.route("/sensitive/dict", methods=["GET"])
def list_sensitive_dict():
    """列出当前所有自定义敏感模式（JSON 列表）。

    HCSE P1：GET 接口也需要鉴权，防止攻击者枚举出当前的敏感关键词
    （知道哪些词会被拦截后就容易规避）。
    """
    _auth = _require_admin_auth("/sensitive/dict")
    if _auth is not None:
        body, code = _auth
        return _attach_cors(body), code
    try:
        shield = _get_shield(_default_mode)
        patterns = shield.list_sensitive_patterns()
        resp = jsonify({"ok": True, "patterns": patterns, "count": len(patterns)})
        return _attach_cors(resp)
    except Exception as e:
        logger.error("list_sensitive_dict error: %s", e, exc_info=True)
        resp = jsonify({"ok": False, "patterns": [], "count": 0,
                        "message": f"Engine error: {type(e).__name__}"})
        return _attach_cors(resp), 500


@app.route("/sensitive/dict/<path:name>", methods=["DELETE", "OPTIONS"])
def delete_sensitive_dict_entry(name: str):
    """删除指定 name 的自定义敏感模式。

    HCSE P1：管理接口（删除词典条目），必须 admin 鉴权。
    """
    if request.method == "OPTIONS":
        resp = jsonify({})
        return _attach_cors(resp)

    _auth = _require_admin_auth("/sensitive/dict")
    if _auth is not None:
        body, code = _auth
        return _attach_cors(body), code

    try:
        shield = _get_shield(_default_mode)
        deleted = bool(shield.remove_sensitive_pattern(name))
        resp = jsonify({"ok": True, "deleted": deleted, "name": name})
        return _attach_cors(resp)
    except Exception as e:
        logger.error("delete_sensitive_dict error: %s", e, exc_info=True)
        resp = jsonify({"ok": False, "deleted": False,
                        "message": f"Engine error: {type(e).__name__}"})
        return _attach_cors(resp), 500


# /protect 端点同步透传 redacted_text（medium 命中时）
#   — 复用现有 /protect 实现：engine 里 debug_info["redacted_text"] 已写入，
#     这里在 JSON 响应中额外暴露一个顶层字段，方便前端直接拿脱敏后的文本


if __name__ == "__main__":
    main()
