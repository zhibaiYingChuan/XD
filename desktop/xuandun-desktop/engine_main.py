# DEPRECATED: 此文件已废弃，请使用 engine_flask.py 作为统一引擎入口
# 迁移说明：engine_flask.py 提供相同功能且性能更优
import warnings
warnings.warn("engine_main.py is deprecated, use engine_flask.py instead", DeprecationWarning, stacklevel=2)

"""道体·玄盾 桌面端引擎入口。

作为 Tauri Sidecar 运行，提供 HTTP API 服务。
监听 localhost:18765，供桌面应用和外部 Agent 调用。
"""

import argparse
import json
import logging
import signal
import sys
import time
import uuid
import concurrent.futures
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from typing import Dict, Optional

from daoti_xuandun import XuanDun, XuanDunConfig, DefenseLevel


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stderr)],
)
logger = logging.getLogger("xuandun-engine")

_MODE_MAP = {
    "high_security": DefenseLevel.STRICT,
    "balanced": DefenseLevel.STANDARD,
    "low_false_positive": DefenseLevel.BASIC,
}

_shields: Dict[str, XuanDun] = {}
_default_mode: str = "balanced"
_start_time: float = time.time()
_total_requests: int = 0
_total_blocked: int = 0
_executor: Optional[concurrent.futures.ThreadPoolExecutor] = None


def _get_executor() -> concurrent.futures.ThreadPoolExecutor:
    global _executor
    if _executor is None or _executor._shutdown:
        _executor = concurrent.futures.ThreadPoolExecutor(max_workers=4, thread_name_prefix="xuandun-worker")
    return _executor


def _get_shield(mode: str) -> XuanDun:
    if mode not in _shields:
        logger.info("Creating new XuanDun instance for mode=%s", mode)
        level = _MODE_MAP.get(mode, DefenseLevel.STANDARD)
        config = XuanDunConfig.for_level(level)
        _shields[mode] = XuanDun(config)
        logger.info("XuanDun instance created for mode=%s", mode)
    else:
        logger.debug("Reusing cached XuanDun instance for mode=%s", mode)
    return _shields[mode]


class EngineHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        logger.info(format, *args)

    def _send_json(self, data: dict, status: int = 200):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        global _total_requests, _total_blocked, _start_time

        if self.path == "/health":
            self._send_json({"status": "ok", "version": "1.0.0"})
        elif self.path == "/status":
            uptime = time.time() - _start_time
            block_rate = _total_blocked / max(1, _total_requests)
            self._send_json({
                "running": True,
                "mode": _default_mode,
                "uptime": round(uptime, 1),
                "total_requests": _total_requests,
                "total_blocked": _total_blocked,
                "block_rate": round(block_rate, 4),
                "defense_level": _default_mode,
                "cached_modes": list(_shields.keys()),
            })
        elif self.path == "/benchmark":
            shield = _get_shield(_default_mode)
            lats = []
            for _ in range(10):
                s = time.perf_counter()
                shield.protect("Write a Python function", session_id="bench")
                lats.append((time.perf_counter() - s) * 1000)
            avg = sum(lats) / len(lats)
            p99 = sorted(lats)[9]
            self._send_json({
                "avg_ms": round(avg, 1),
                "p99_ms": round(p99, 1),
                "min_ms": round(min(lats), 1),
                "max_ms": round(max(lats), 1),
                "samples": 10,
            })
        else:
            self._send_json({"error": "not found"}, 404)

    def do_POST(self):
        global _total_requests, _total_blocked

        if self.path != "/protect":
            self._send_json({"error": "not found"}, 404)
            return

        try:
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length)
            data = json.loads(raw) if raw else {}
        except (json.JSONDecodeError, ValueError):
            self._send_json({"error": "invalid json"}, 400)
            return

        text = data.get("text", "")
        session = data.get("session", str(uuid.uuid4())[:8])
        mode = data.get("mode", _default_mode)

        if not text:
            self._send_json({"error": "text is required"}, 400)
            return

        try:
            t_start = time.perf_counter()
            shield = _get_shield(mode)
            t_shield = time.perf_counter()

            executor = _get_executor()
            future = executor.submit(shield.protect, text, session)
            try:
                result = future.result(timeout=5.0)
            except concurrent.futures.TimeoutError:
                logger.error("protect() timed out after 5s for session=%s mode=%s", session, mode)
                self._send_json({
                    "allowed": True,
                    "trust_level": "UNKNOWN",
                    "reject_stage": None,
                    "domain_distance": None,
                    "timing_distance": None,
                    "fallback": True,
                    "message": "Engine timeout",
                })
                return

            t_protect = time.perf_counter()
            logger.info("timing: get_shield=%.1fms protect=%.1fms total=%.1fms session=%s mode=%s",
                       (t_shield-t_start)*1000, (t_protect-t_shield)*1000, (t_protect-t_start)*1000, session, mode)

            _total_requests += 1
            if not result.allowed:
                _total_blocked += 1

            response = {
                "allowed": result.allowed,
                "trust_level": result.trust_level.value if hasattr(result.trust_level, "value") else str(result.trust_level),
                "reject_stage": result.reject_stage,
                "domain_distance": result.domain_distance,
                "timing_distance": result.timing_distance,
            }
            self._send_json(response)

        except Exception as e:
            logger.error("Protect error: %s", e, exc_info=True)
            self._send_json({
                "allowed": True,
                "trust_level": "UNKNOWN",
                "reject_stage": None,
                "domain_distance": None,
                "timing_distance": None,
                "fallback": True,
                "message": f"Engine error: {str(e)}",
            })


def main():
    parser = argparse.ArgumentParser(description="道体·玄盾 桌面端引擎")
    parser.add_argument("--port", type=int, default=18765, help="监听端口")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="监听地址")
    parser.add_argument("--mode", type=str, default="balanced",
                        choices=["high_security", "balanced", "low_false_positive"],
                        help="默认防护模式")
    args = parser.parse_args()

    global _default_mode
    _default_mode = args.mode

    _get_shield(_default_mode)
    for mode in _MODE_MAP:
        if mode != _default_mode:
            _get_shield(mode)

    server = ThreadingHTTPServer((args.host, args.port), EngineHandler)
    server.timeout = 1

    def shutdown(signum, frame):
        logger.info("Shutting down engine...")
        if _executor is not None:
            _executor.shutdown(wait=False)
        server.shutdown()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    logger.info("道体·玄盾引擎启动: %s:%d (mode=%s)", args.host, args.port, args.mode)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        logger.info("Engine stopped.")


if __name__ == "__main__":
    main()
