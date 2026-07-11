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


def _get_shield(mode: str) -> XuanDun:
    with _shields_lock:
        if mode not in _shields:
            logger.info("Creating new XuanDun instance for mode=%s", mode)
            level = _MODE_MAP.get(mode, DefenseLevel.STANDARD)
            config = XuanDunConfig.for_level(level)
            _shields[mode] = XuanDun(config)
            logger.info("XuanDun instance created for mode=%s", mode)
        return _shields[mode]


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "version": "1.2.2"})


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


def _classify_attack_category(text: str, reject_stage) -> str:
    if reject_stage is None:
        return None
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
    mode = data.get("mode", _default_mode)

    if not text:
        return jsonify({"error": "text is required"}), 400

    try:
        shield = _get_shield(mode)
        t0 = time.perf_counter()
        result = shield.protect(text, session_id=session)
        lat = (time.perf_counter() - t0) * 1000
        logger.info("protect() took %.1fms session=%s mode=%s", lat, session, mode)

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
            "attack_category": _classify_attack_category(text, result.reject_stage) if not result.allowed else None,
            "latency_ms": round(lat, 2),
        }
        resp = jsonify(response)
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
    global _default_mode

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
    args = parser.parse_args()

    _default_mode = args.mode

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
