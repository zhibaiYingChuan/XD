# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白
# 本文件受道体研究许可证 v1.0 约束，禁止逆向工程和再分发
# 详见 LICENSE 文件

"""道体·玄盾 桌面端引擎入口 - 使用 Flask 替代 http.server。

Flask 内置的开发服务器在 Windows 上更稳定。
生产环境应使用 waitress 或 gunicorn。
"""

import argparse
import json
import logging
import os
import signal
import sys
import threading
import time
import uuid
from collections import deque, Counter

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

_DEBUG_TOKEN = os.environ.get("XUANDUN_DEBUG_TOKEN", "")
_ALLOWED_ORIGINS = ("tauri://localhost", "http://tauri.localhost")

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


def _get_shield(mode: str) -> XuanDun:
    with _shields_lock:
        if mode not in _shields:
            logger.info("Creating new XuanDun instance for mode=%s", mode)
            level = _MODE_MAP.get(mode, DefenseLevel.STANDARD)
            config = XuanDunConfig.for_level(level)
            shield = XuanDun(config)
            # 桌面端强制启用保护模式，无需等待样本积累
            # 内置攻击/安全原型已提供充分的初始防护能力
            shield.switch_mode("protecting")

            # 如果有其他模式的 shield 已有学习数据，迁移之
            if _shields:
                source = max(_shields.values(), key=lambda s: s.domain_awareness.call_count)
                if source.domain_awareness.call_count > 0:
                    logger.info(
                        "Preparing to transfer learning data from mode with call_count=%d",
                        source.domain_awareness.call_count,
                    )
                    _transfer_learning_data(shield, source)

            _shields[mode] = shield
            logger.info("XuanDun instance created for mode=%s (mode=protecting)", mode)
        return _shields[mode]


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "version": "1.2.3"})


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
    try:
        shield = _get_shield(_default_mode)
        ls = shield.get_learning_status()
        learning_mode = ls.get("mode", "protecting")
        learning_progress = ls.get("learning_progress", 1.0)
        sample_count = ls.get("sample_count", 0)
    except Exception:
        pass

    return jsonify({
        "running": running,
        "mode": _default_mode,
        "learning_mode": learning_mode,
        "learning_progress": learning_progress,
        "sample_count": sample_count,
        "uptime": round(uptime, 1),
        "total_requests": total_req,
        "total_blocked": total_blk,
        "block_rate": round(block_rate, 4),
        "cached_modes": list(_shields.keys()),
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
        return jsonify({"error": str(e)}), 500


@app.route("/mode/switch", methods=["POST", "OPTIONS"])
def switch_learning_mode():
    """手动切换观察/保护模式。

    Body: {"mode": "observing" | "protecting"}
    """
    if request.method == "OPTIONS":
        resp = jsonify({})
        return _attach_cors(resp)

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
        return jsonify({"error": str(e)}), 500


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
        return jsonify({"error": str(e)}), 500


# ── 企业级运维：逃生通道 + 灰度部署 ──

@app.route("/emergency/bypass", methods=["GET", "POST", "OPTIONS"])
def emergency_bypass():
    """逃生通道：紧急放行所有请求。

    GET: 返回当前状态
    POST: {"enabled": true/false} 设置开关
    """
    if request.method == "OPTIONS":
        resp = jsonify({})
        return _attach_cors(resp)

    try:
        shield = _get_shield(_default_mode)
        if request.method == "POST":
            data = request.get_json(silent=True) or {}
            enabled = bool(data.get("enabled", False))
            result = shield.set_emergency_bypass(enabled)
            logger.warning("Emergency bypass %s: %s",
                           "ENABLED" if enabled else "DISABLED", result)
            resp = jsonify(result)
        else:
            resp = jsonify({
                "emergency_bypass": shield.get_emergency_bypass(),
            })
        return _attach_cors(resp)
    except Exception as e:
        logger.error("emergency_bypass error: %s", e)
        return jsonify({"error": str(e)}), 500


@app.route("/gray/deploy", methods=["GET", "POST", "OPTIONS"])
def gray_deploy():
    """灰度部署：按比例拦截请求。

    GET: 返回当前比例
    POST: {"ratio": 0.1} 设置比例（0.0~1.0）
    """
    if request.method == "OPTIONS":
        resp = jsonify({})
        return _attach_cors(resp)

    try:
        shield = _get_shield(_default_mode)
        if request.method == "POST":
            data = request.get_json(silent=True) or {}
            ratio = float(data.get("ratio", 1.0))
            result = shield.set_gray_deploy_ratio(ratio)
            logger.info("Gray deploy ratio set: %s", result)
            resp = jsonify(result)
        else:
            resp = jsonify({
                "gray_deploy_ratio": shield.get_gray_deploy_ratio(),
            })
        return _attach_cors(resp)
    except Exception as e:
        logger.error("gray_deploy error: %s", e)
        return jsonify({"error": str(e)}), 500


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
        return jsonify({"error": str(e)}), 500


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
    """接收告警事件并分发到所有已配置的通道。"""
    if request.method == "OPTIONS":
        resp = jsonify({})
        return _attach_cors(resp)
    data = request.get_json(silent=True) or {}
    try:
        event = AlertEvent(
            event_type=data.get("event_type", "block"),
            severity=data.get("severity", "info"),
            timestamp=data.get("timestamp", ""),
            attack_category=data.get("attack_category"),
            trust_level=data.get("trust_level", ""),
            reject_stage=data.get("reject_stage"),
            text_preview=data.get("text_preview", ""),
            engine_mode=data.get("engine_mode", ""),
            extra=data.get("extra", {}),
        )
        sent = _alert_manager.dispatch(event)
        resp = jsonify({"status": "ok", "sent_count": sent})
        return _attach_cors(resp)
    except Exception as e:
        logger.error("Alert dispatch error: %s", e, exc_info=True)
        resp = jsonify({"status": "error", "message": str(e)})
        return _attach_cors(resp)


@app.route("/notifiers/config", methods=["POST", "OPTIONS"])
def configure_notifiers():
    """批量配置告警通道。Body: {"channels": {"dingtalk": {...}, ...}}"""
    if request.method == "OPTIONS":
        resp = jsonify({})
        return _attach_cors(resp)
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
    """发送测试告警。Body: {"channel": "dingtalk", "config": {...}}"""
    if request.method == "OPTIONS":
        resp = jsonify({})
        return _attach_cors(resp)
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
        text_preview="这是一条来自道体·玄盾的测试告警",
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

    if not text:
        return jsonify({"error": "text is required"}), 400

    try:
        shield = _get_shield(_default_mode)
        t0 = time.perf_counter()
        result = shield.protect(text, session_id=session)
        lat = (time.perf_counter() - t0) * 1000
        logger.info("protect() took %.1fms session=%s mode=%s", lat, session, _default_mode)

        with _stats_lock:
            global _total_requests, _total_blocked
            _total_requests += 1
            if not result.allowed:
                _total_blocked += 1

        response = {
            "allowed": result.allowed,
            "trust_level": result.trust_level.value if hasattr(result.trust_level, "value") else str(result.trust_level),
            "reject_stage": result.reject_stage,
            "domain_distance": result.domain_distance,
            "timing_distance": result.timing_distance,
            "attack_category": _classify_attack_category(text, result.reject_stage),
            "latency_ms": round(lat, 2),
        }
        resp = jsonify(response)

        # 检查是否需要保存学习快照（按 call_count 增长阈值触发）
        _maybe_save_snapshot(_default_mode)

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
        })
        return _attach_cors(resp)


@app.route("/set-mode", methods=["POST", "OPTIONS"])
def set_mode():
    if request.method == "OPTIONS":
        resp = jsonify({})
        return _attach_cors(resp)

    global _default_mode
    data = request.get_json(silent=True) or {}
    new_mode = data.get("mode", "")
    if new_mode not in _MODE_MAP:
        return jsonify({"error": f"Invalid mode: {new_mode}"}), 400

    _default_mode = new_mode
    _get_shield(new_mode)
    _save_learning_snapshot()
    logger.info("Mode switched to %s", new_mode)
    return jsonify({"status": "ok", "mode": new_mode})


@app.route("/warmup", methods=["POST", "OPTIONS"])
def warmup():
    if request.method == "OPTIONS":
        resp = jsonify({})
        return _attach_cors(resp)

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
        logger.info("Warmup completed: %d safe, %d attack texts for mode %s", len(safe_texts), len(attack_texts), mode)
        return jsonify({"status": "ok", "safe_count": len(safe_texts), "attack_count": len(attack_texts), "mode": mode})
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

    parser = argparse.ArgumentParser(description="道体·玄盾 桌面端引擎")
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

    logger.info("道体·玄盾引擎启动: %s:%d (mode=%s)", args.host, args.port, args.mode)

    try:
        from waitress import serve
        logger.info("Using waitress production WSGI server")
        serve(app, host=args.host, port=args.port, threads=4)
    except ImportError:
        logger.warning("waitress not available, falling back to Flask development server")
        app.run(host=args.host, port=args.port, threaded=True, debug=False)


if __name__ == "__main__":
    main()
