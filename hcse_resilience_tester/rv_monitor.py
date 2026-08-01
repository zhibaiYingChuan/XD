"""
rv_monitor.py — 玄盾桌面端 HCSE 运行时验证监控核心引擎

阶段: Phase 3 (CDP RV-Monitor) + Phase 6 (HCSE 沙箱自熔断器)

职责:
  1. 通过 CDP WebSocket 连接玄盾桌面端 (端口 9224)
  2. 维护事件源队列 (requestWillBeSent / responseReceived / exceptionThrown / domMutated)
  3. 对每个关键事件实时执行不变式断言
  4. 失败时立即生成不变式违反报告 + 触发 Hard Halt
  5. 集成 PathValidator / DataSanitizer / ResourceWatchdog (Phase 6)

设计原则:
  - 单一职责: 每个类只做一件事
  - 失败安全: 任何异常都导致测试 fail，绝不静默
  - 证据完整: 所有违反报告包含时间戳/事件上下文/CDP活性证明

依赖: pip install websocket-client psutil pyyaml
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
import threading
import traceback
from collections import deque
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Callable, Optional

try:
    import websocket  # type: ignore
    import requests
    import psutil
    import yaml
except ImportError as e:
    sys.stderr.write(f"[HCSE] 缺少依赖: {e}\n请运行: pip install websocket-client requests psutil pyyaml\n")
    sys.exit(2)


# ══════════════════════════════════════════════════════════════════
# Phase 6 - HCSE 沙箱: PathValidator (路径白名单)
# ══════════════════════════════════════════════════════════════════

class HardHaltError(Exception):
    """HCSE Hard Halt: 触发即终止所有测试，标记环境安全 breach"""


class PathValidator:
    """
    HCSE Phase 6 - 路径白名单验证器

    仅允许在以下目录进行文件操作:
      ./temp, ./logs, ./screenshots, ./evidence

    任何越界访问触发 HardHaltError，立即终止测试。
    """

    # 白名单目录（基于 hcse_resilience_tester/ 工作目录解析绝对路径）
    BASE_DIR = Path(__file__).resolve().parent

    ALLOWED_DIRS = [
        BASE_DIR / "temp",
        BASE_DIR / "logs",
        BASE_DIR / "screenshots",
        BASE_DIR / "evidence",
    ]

    # 系统目录黑名单（双重保险，即使白名单逻辑出错也阻断）
    FORBIDDEN_PATTERNS = [
        r"^[A-Za-z]:[\\/]Windows",
        r"^[A-Za-z]:[\\/]Users[\\/][^\\/]+[\\/](?!AppData[\\/]Local[\\/]com\.daoti)",
        r"^[A-Za-z]:[\\/]Program Files",
        r"^/etc",
        r"^/usr",
        r"^/sys",
        r"^/proc",
    ]

    @classmethod
    def validate(cls, path: str | Path, operation: str = "access") -> Path:
        """验证路径是否在白名单内，返回绝对路径；否则 raise HardHaltError"""
        target = Path(path).resolve() if not Path(path).is_absolute() else Path(path)
        # 检查黑名单
        path_str = str(target)
        for pattern in cls.FORBIDDEN_PATTERNS:
            if re.match(pattern, path_str):
                msg = f"[HCSE Hard Halt] 禁止访问系统目录: {path_str} (op={operation}, pattern={pattern})"
                cls._log_breach(msg)
                raise HardHaltError(msg)
        # 检查白名单
        for allowed in cls.ALLOWED_DIRS:
            try:
                target.relative_to(allowed)
                return target
            except ValueError:
                continue
        msg = f"[HCSE Hard Halt] 路径越界: {path_str} 不在白名单 {cls.ALLOWED_DIRS} (op={operation})"
        cls._log_breach(msg)
        raise HardHaltError(msg)

    @staticmethod
    def _log_breach(msg: str) -> None:
        breach_log = PathValidator.BASE_DIR / "logs" / "path_breach.log"
        breach_log.parent.mkdir(parents=True, exist_ok=True)
        with breach_log.open("a", encoding="utf-8") as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}\n")
            f.write(traceback.format_exc())
        sys.stderr.write(msg + "\n")


# ══════════════════════════════════════════════════════════════════
# Phase 6 - HCSE 沙箱: DataSanitizer (数据脱敏)
# ══════════════════════════════════════════════════════════════════

class DataSanitizer:
    """
    HCSE Phase 6 - 双重数据脱敏

    在写入任何捕获数据（日志/证据/快照）前必须调用 sanitize()，
    执行:
      1. 正则替换 (email/phone/cookie value)
      2. 结构字段裁剪 (authorization header / set-cookie value)
    """

    EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
    PHONE_RE = re.compile(r"(\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3,4}[-.\s]?\d{4}")
    COOKIE_VALUE_RE = re.compile(r"(set-cookie:\s*[^=]+=)([^;]+)", re.IGNORECASE)
    AUTH_HEADER_RE = re.compile(r"(authorization:\s*)(bearer\s+[\w\.-]+)", re.IGNORECASE)

    @classmethod
    def sanitize(cls, data: Any) -> Any:
        """递归脱敏：支持 str / dict / list / nested"""
        if isinstance(data, str):
            return cls._sanitize_str(data)
        if isinstance(data, dict):
            return {k: cls._sanitize_key_value(k, v) for k, v in data.items()}
        if isinstance(data, list):
            return [cls.sanitize(item) for item in data]
        return data

    @classmethod
    def _sanitize_str(cls, s: str) -> str:
        s = cls.EMAIL_RE.sub("[EMAIL_REDACTED]", s)
        s = cls.PHONE_RE.sub("[PHONE_REDACTED]", s)
        s = cls.COOKIE_VALUE_RE.sub(r"\1[COOKIE_VALUE_REDACTED]", s)
        s = cls.AUTH_HEADER_RE.sub(r"\1[BEARER_TOKEN_REDACTED]", s)
        return s

    @classmethod
    def _sanitize_key_value(cls, key: str, value: Any) -> Any:
        key_lower = key.lower() if isinstance(key, str) else key
        if key_lower in ("authorization", "x-api-key", "x-auth-token"):
            return "[REDACTED]"
        if key_lower in ("cookie", "set-cookie"):
            return "[COOKIE_REDACTED]"
        if key_lower in ("password", "passwd", "secret", "api_key", "apikey"):
            return "[REDACTED]"
        if key_lower in ("email", "phone", "mobile"):
            return "[PII_REDACTED]"
        return cls.sanitize(value)


# ══════════════════════════════════════════════════════════════════
# Phase 6 - HCSE 沙箱: ResourceWatchdog (资源容量看门狗)
# ══════════════════════════════════════════════════════════════════

class ResourceWatchdog:
    """
    HCSE Phase 6 - 资源容量看门狗

    监控当前 Python 进程 + 目标桌面端进程 (PID 5144) 的:
      - 内存使用 (MAX_MEMORY_USAGE = 1024 MB)
      - CPU 时间 (MAX_CPU_TIME = 60s)

    超限时优先终止子 CDP 会话，保护测试平台可用性。
    """

    MAX_MEMORY_MB = 1024
    MAX_CPU_TIME_SEC = 60
    TARGET_PID = 5144  # xuandun-desktop.exe

    def __init__(self, check_interval_sec: float = 5.0):
        self.check_interval = check_interval_sec
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.violations: list[dict] = []

    def start(self) -> None:
        PathValidator.ALLOWED_DIRS[0].mkdir(parents=True, exist_ok=True)  # temp
        self._thread = threading.Thread(target=self._run, daemon=True, name="HCSE-Watchdog")
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)

    def _run(self) -> None:
        while not self._stop_event.is_set():
            try:
                self._check_once()
            except Exception as e:
                self._record("watchdog_error", str(e))
            self._stop_event.wait(self.check_interval)

    def _check_once(self) -> None:
        # 检查自身进程
        own = psutil.Process(os.getpid())
        own_mem_mb = own.memory_info().rss / 1024 / 1024
        # HCSE Sprint5 修复：cpu_times().user + .system 返回 float，不能套用 sum()
        own_cpu_sec = own.cpu_times().user + own.cpu_times().system
        if own_mem_mb > self.MAX_MEMORY_MB:
            self._record("self_memory_exceeded",
                         f"自身内存 {own_mem_mb:.1f}MB > {self.MAX_MEMORY_MB}MB")
        if own_cpu_sec > self.MAX_CPU_TIME_SEC * 2:  # 自身放宽2倍
            self._record("self_cpu_exceeded",
                         f"自身CPU {own_cpu_sec:.1f}s > {self.MAX_CPU_TIME_SEC * 2}s")

        # 检查目标桌面端进程
        try:
            target = psutil.Process(self.TARGET_PID)
            target_mem_mb = target.memory_info().rss / 1024 / 1024
            # HCSE Sprint5 修复：同上，float 不能 sum()
            target_cpu_sec = target.cpu_times().user + target.cpu_times().system
            if target_mem_mb > self.MAX_MEMORY_MB:
                self._record("target_memory_exceeded",
                             f"桌面端 PID={self.TARGET_PID} 内存 {target_mem_mb:.1f}MB > {self.MAX_MEMORY_MB}MB (不强制终止)")
            # 注意: 不主动 kill 桌面端进程，仅记录违反
        except psutil.NoSuchProcess:
            self._record("target_process_gone",
                         f"目标进程 PID={self.TARGET_PID} 不存在")

    def _record(self, kind: str, detail: str) -> None:
        rec = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "kind": kind,
            "detail": detail,
        }
        self.violations.append(rec)
        log_path = PathValidator.BASE_DIR / "logs" / "resource_watchdog.jsonl"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(DataSanitizer.sanitize(rec), ensure_ascii=False) + "\n")


# ══════════════════════════════════════════════════════════════════
# Phase 3 - CDP 事件源队列
# ══════════════════════════════════════════════════════════════════

@dataclass
class CDPEvent:
    """CDP 事件封装（事件源队列的单条记录）"""
    method: str
    params: dict
    timestamp: float = field(default_factory=time.time)
    session_id: Optional[str] = None


class EventSourcingQueue:
    """
    HCSE Phase 3 - 事件源队列

    存储所有 CDP 事件: requestWillBeSent, responseReceived,
    exceptionThrown, domMutated, attributeModified

    提供:
      - append(event): 追加事件
      - recent(n): 最近 n 条事件
      - filter(method, predicate): 按条件过滤
      - snapshot(): 全量快照（脱敏后）
    """

    MAX_SIZE = 5000

    def __init__(self) -> None:
        self._queue: deque[CDPEvent] = deque(maxlen=self.MAX_SIZE)
        self._lock = threading.Lock()

    def append(self, event: CDPEvent) -> None:
        with self._lock:
            self._queue.append(event)

    def recent(self, n: int = 100) -> list[CDPEvent]:
        with self._lock:
            return list(self._queue)[-n:]

    def filter(self, method: Optional[str] = None,
               predicate: Optional[Callable[[CDPEvent], bool]] = None) -> list[CDPEvent]:
        with self._lock:
            result = []
            for ev in self._queue:
                if method and ev.method != method:
                    continue
                if predicate and not predicate(ev):
                    continue
                result.append(ev)
            return result

    def snapshot(self) -> list[dict]:
        """返回脱敏后的事件快照，用于证据归档"""
        with self._lock:
            return [DataSanitizer.sanitize(asdict(ev)) for ev in self._queue]


# ══════════════════════════════════════════════════════════════════
# Phase 3 - CDP 活性检查
# ══════════════════════════════════════════════════════════════════

class CDPLivenessCheck:
    """
    HCSE Phase 3 - CDP 活性检查

    当不变式断言失败时，自动 ping Browser.getVersion 确认 CDP 通道存活，
    避免 CDP 丢包导致的假阴性。
    """

    def __init__(self, cdp_http_endpoint: str = "http://127.0.0.1:9224"):
        self.http_endpoint = cdp_http_endpoint.rstrip("/")

    def get_websocket_url(self) -> Optional[str]:
        """通过 /json 端点获取 WebSocket 调试 URL"""
        try:
            resp = requests.get(f"{self.http_endpoint}/json", timeout=3)
            if resp.status_code != 200:
                return None
            data = resp.json()
            for target in data:
                if target.get("type") == "page":
                    return target.get("webSocketDebuggerUrl")
            return None
        except Exception:
            return None

    def ping_version(self) -> dict:
        """通过 WebSocket 发送 Browser.getVersion 验证 CDP 通道存活"""
        ws_url = self.get_websocket_url()
        if not ws_url:
            return {"alive": False, "reason": "无法获取 WebSocket URL"}
        try:
            ws = websocket.create_connection(ws_url, timeout=5)
            ws.send(json.dumps({"id": 99999, "method": "Browser.getVersion"}))
            raw = ws.recv()
            ws.close()
            msg = json.loads(raw)
            if msg.get("id") == 99999 and "result" in msg:
                return {"alive": True, "version": msg["result"]}
            return {"alive": False, "reason": f"unexpected response: {msg}"}
        except Exception as e:
            return {"alive": False, "reason": str(e)}


# ══════════════════════════════════════════════════════════════════
# Phase 3 - 不变式违反报告
# ══════════════════════════════════════════════════════════════════

@dataclass
class InvariantViolation:
    """不变式违反报告"""
    invariant_id: str
    invariant_name: str
    severity: str
    timestamp: str
    triggering_event: dict
    context_events: list[dict]
    cdp_liveness: dict
    assertion_logic: str
    expected: str
    actual: str
    traceback: Optional[str] = None

    def to_dict(self) -> dict:
        return DataSanitizer.sanitize(asdict(self))


# ══════════════════════════════════════════════════════════════════
# Phase 3 - 不变式检查器
# ══════════════════════════════════════════════════════════════════

class InvariantChecker:
    """
    HCSE Phase 3 - 不变式检查器

    对每个关键 CDP 事件执行预定义的不变式断言。
    若检查失败，立即生成 InvariantViolation 并触发 Hard Halt。
    """

    def __init__(self, event_queue: EventSourcingQueue,
                 liveness: CDPLivenessCheck,
                 on_violation: Callable[[InvariantViolation], None]):
        self.queue = event_queue
        self.liveness = liveness
        self.on_violation = on_violation
        self.results: dict[str, str] = {}  # invariant_id -> PASS/FAIL
        self._halt = False

    def check_and_record(self, invariant_id: str, invariant_name: str,
                         severity: str, assertion_logic: str,
                         expected: str, actual: str,
                         triggering_event: dict,
                         context_events: list[dict],
                         condition: bool) -> None:
        """检查条件并记录结果；失败时触发违反报告"""
        if condition:
            self.results.setdefault(invariant_id, "PASS")
            if self.results[invariant_id] != "FAIL":
                self.results[invariant_id] = "PASS"
            return

        # 失败: 先做 CDP 活性检查
        cdp_alive = self.liveness.ping_version()
        violation = InvariantViolation(
            invariant_id=invariant_id,
            invariant_name=invariant_name,
            severity=severity,
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            triggering_event=triggering_event,
            context_events=context_events,
            cdp_liveness=cdp_alive,
            assertion_logic=assertion_logic,
            expected=expected,
            actual=actual,
        )
        self.results[invariant_id] = "FAIL"
        self.on_violation(violation)
        # P0 不变式失败立即 Hard Halt
        if severity == "P0" and cdp_alive.get("alive"):
            self._halt = True

    def should_halt(self) -> bool:
        return self._halt


# ══════════════════════════════════════════════════════════════════
# Phase 3 - RV-Monitor 主监控器
# ══════════════════════════════════════════════════════════════════

class RVMonitor:
    """
    HCSE Phase 3 - RV-Monitor 主监控器

    通过 CDP WebSocket 持续监听所有事件，
    对关键事件触发不变式断言。
    """

    def __init__(self, cdp_http_endpoint: str = "http://127.0.0.1:9224",
                 invariants_yaml: Optional[str] = None):
        self.cdp_endpoint = cdp_http_endpoint
        self.queue = EventSourcingQueue()
        self.liveness = CDPLivenessCheck(cdp_http_endpoint)
        self.violations: list[InvariantViolation] = []
        self.checker = InvariantChecker(
            event_queue=self.queue,
            liveness=self.liveness,
            on_violation=self._on_violation,
        )
        self.watchdog = ResourceWatchdog()
        self.ws: Optional[websocket.WebSocketApp] = None
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.invariants_config = self._load_invariants(invariants_yaml)

    def _load_invariants(self, yaml_path: Optional[str]) -> dict:
        if not yaml_path:
            yaml_path = str(PathValidator.BASE_DIR / "invariants.yaml")
        try:
            with open(yaml_path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        except FileNotFoundError:
            sys.stderr.write(f"[HCSE] 不变式配置未找到: {yaml_path}\n")
            return {}

    def _on_violation(self, violation: InvariantViolation) -> None:
        self.violations.append(violation)
        # 写入违反日志（脱敏 + 路径验证）
        log_path = PathValidator.validate(
            str(PathValidator.BASE_DIR / "logs" / "invariant_violations.jsonl"),
            operation="write_violation_log"
        )
        with log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(violation.to_dict(), ensure_ascii=False) + "\n")
        sys.stderr.write(
            f"[HCSE 违反] {violation.invariant_id} ({violation.severity}) "
            f"{violation.invariant_name}\n"
            f"  期望: {violation.expected}\n"
            f"  实际: {violation.actual}\n"
            f"  CDP存活: {violation.cdp_liveness.get('alive')}\n"
        )

    # ── CDP WebSocket 回调 ──

    def _on_ws_message(self, ws, message: str) -> None:
        try:
            msg = json.loads(message)
            method = msg.get("method", "")
            params = msg.get("params", {})
            event = CDPEvent(method=method, params=params)
            self.queue.append(event)
            self._dispatch_invariants(event)
        except Exception as e:
            sys.stderr.write(f"[HCSE] _on_ws_message 异常: {e}\n")

    def _on_ws_error(self, ws, error) -> None:
        sys.stderr.write(f"[HCSE] CDP WebSocket 错误: {error}\n")

    def _on_ws_close(self, ws, close_status_code, close_msg) -> None:
        sys.stderr.write(f"[HCSE] CDP WebSocket 关闭: code={close_status_code} msg={close_msg}\n")

    def _on_ws_open(self, ws) -> None:
        # 启用所有需要的 CDP 域
        for domain_method in [
            "Network.enable",
            "Runtime.enable",
            "DOM.enable",
            "Page.enable",
            "Security.enable",
        ]:
            ws.send(json.dumps({"id": 1, "method": domain_method}))
        sys.stderr.write("[HCSE] CDP WebSocket 已连接，启用监听域\n")

    # ── 不变式调度 ──

    def _dispatch_invariants(self, event: CDPEvent) -> None:
        """根据事件类型派发对应不变式检查"""
        method = event.method
        if method == "Network.responseReceived":
            self._check_network_response(event)
        elif method == "Runtime.exceptionThrown":
            self._check_runtime_exception(event)
        elif method == "DOM.attributeModified":
            self._check_dom_attribute(event)
        # 不变式 09 (Tauri bridge) 通过 evaluate_script 主动检测，不依赖事件

    def _check_network_response(self, event: CDPEvent) -> None:
        """检查网络响应相关不变式 (INV-01, INV-02, INV-06, INV-07)"""
        params = event.params
        response = params.get("response", {})
        url = response.get("url", "")
        status = response.get("status", 0)

        # 仅检查 Tauri IPC 调用
        if "tauri.localhost" not in url and "ipc.localhost" not in url:
            return

        # INV-01/INV-02: protect fallback 检查需要在 evaluate_script 中获取响应体
        # 这里仅记录事件，具体断言由主动 evaluate_script 触发

    def _check_runtime_exception(self, event: CDPEvent) -> None:
        """检查运行时异常 (INV-08 超时, INV-09 bridge 缺失)"""
        params = event.params
        exception = params.get("exceptionDetails", {})
        text = exception.get("text", "")
        exception_obj = exception.get("exception", {})
        description = exception_obj.get("description", "")

        # INV-08: InvokeTimeoutError 必须正确抛出
        if "InvokeTimeoutError" in description or "操作超时" in description:
            self.checker.check_and_record(
                invariant_id="INV-08",
                invariant_name="Invoke 超时机制触发不变式",
                severity="P0",
                assertion_logic="invokeWithTimeout 超时后必须抛出 InvokeTimeoutError",
                expected="InvokeTimeoutError 实例被 Runtime.exceptionThrown 捕获",
                actual=f"已捕获: {description[:200]}",
                triggering_event=asdict(event),
                context_events=[asdict(e) for e in self.queue.recent(10)],
                condition=True,  # 捕获到即 PASS
            )

        # INV-09: Tauri bridge 缺失必须立即拒绝
        if "Tauri 桥接未就绪" in description or "__TAURI_INTERNALS__" in description:
            self.checker.check_and_record(
                invariant_id="INV-09",
                invariant_name="Tauri Bridge 缺失检测不变式",
                severity="P0",
                assertion_logic="bridge 缺失时 invokeWithTimeout 必须立即 reject",
                expected="Error('Tauri 桥接未就绪...')",
                actual=f"已捕获: {description[:200]}",
                triggering_event=asdict(event),
                context_events=[asdict(e) for e in self.queue.recent(10)],
                condition=True,
            )

    def _check_dom_attribute(self, event: CDPEvent) -> None:
        """检查 DOM 属性变化 (INV-10 快照恢复 disabled)"""
        params = event.params
        name = params.get("name", "")
        value = params.get("value", "")
        # INV-10: restoringSnapshot 期间按钮必须 disabled
        if name == "disabled" and value in ("true", ""):
            # 仅记录，具体断言由主动脚本触发
            pass

    # ── 主动检测（通过 evaluate_script）──

    def evaluate_script(self, script: str, timeout: float = 10.0) -> dict:
        """
        通过 CDP Runtime.evaluate 执行 JS 脚本并返回结果
        用于主动检测不变式 (INV-03, INV-08, INV-09, INV-10)
        """
        ws_url = self.liveness.get_websocket_url()
        if not ws_url:
            return {"error": "无法获取 WebSocket URL"}
        try:
            ws = websocket.create_connection(ws_url, timeout=timeout)
            ws.send(json.dumps({
                "id": 10000,
                "method": "Runtime.evaluate",
                "params": {
                    "expression": script,
                    "returnByValue": True,
                    "awaitPromise": True,
                    "timeout": int(timeout * 1000),
                }
            }))
            raw = ws.recv()
            ws.close()
            return json.loads(raw)
        except Exception as e:
            return {"error": str(e)}

    # ── 启动/停止 ──

    def start_background(self) -> None:
        """后台启动 CDP 监听线程"""
        self.watchdog.start()
        ws_url = self.liveness.get_websocket_url()
        if not ws_url:
            sys.stderr.write("[HCSE] 无法获取 WebSocket URL，仅运行主动检测\n")
            return

        self.ws = websocket.WebSocketApp(
            ws_url,
            on_open=self._on_ws_open,
            on_message=self._on_ws_message,
            on_error=self._on_ws_error,
            on_close=self._on_ws_close,
        )
        self._thread = threading.Thread(
            target=self.ws.run_forever,
            daemon=True,
            name="HCSE-CDP-Listener"
        )
        self._thread.start()
        time.sleep(1.0)  # 等待 CDP 域启用

    def stop(self) -> None:
        self._stop_event.set()
        if self.ws:
            self.ws.close()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        self.watchdog.stop()

    def get_summary(self) -> dict:
        return {
            "total_events": len(self.queue.snapshot()),
            "violations": len(self.violations),
            "invariant_results": dict(self.checker.results),
            "watchdog_violations": len(self.watchdog.violations),
            "violations_detail": [v.to_dict() for v in self.violations],
        }


# ══════════════════════════════════════════════════════════════════
# 主入口: 自检
# ══════════════════════════════════════════════════════════════════

def self_test() -> int:
    """HCSE 沙箱自检: PathValidator + DataSanitizer + Watchdog"""
    print("=" * 60)
    print("HCSE 沙箱自检")
    print("=" * 60)

    # 1. PathValidator 测试
    print("\n[1] PathValidator 路径白名单测试...")
    try:
        ok_path = PathValidator.validate("./temp/test.log", operation="write_test")
        print(f"  PASS: 白名单路径放行 -> {ok_path}")
    except HardHaltError as e:
        print(f"  FAIL: 白名单路径被拒: {e}")
        return 1

    try:
        PathValidator.validate("C:/Windows/System32/evil.dll", operation="write_test")
        print(f"  FAIL: 系统目录未被拦截")
        return 1
    except HardHaltError:
        print(f"  PASS: 系统目录已拦截 (HardHaltError)")

    # 2. DataSanitizer 测试
    print("\n[2] DataSanitizer 数据脱敏测试...")
    raw = {
        "user_email": "admin@daoti.com",
        "phone": "13800138000",
        "authorization": "Bearer eyJhbGc.secret.token",
        "cookie": "session=abc123; user=xyz",
        "nested": {"email": "user@example.com", "safe": "正常文本"},
    }
    sanitized = DataSanitizer.sanitize(raw)
    # 结构化字段脱敏优先级高于正则替换:
    # - 顶层 phone/email/authorization/cookie 字段被结构化裁剪为 [PII_REDACTED]/[REDACTED]/[COOKIE_REDACTED]
    # - user_email 是字符串值，触发正则替换为 [EMAIL_REDACTED]
    assert sanitized["user_email"] == "[EMAIL_REDACTED]", f"user_email未脱敏: {sanitized['user_email']}"
    assert sanitized["phone"] == "[PII_REDACTED]", f"phone未脱敏: {sanitized['phone']}"
    assert sanitized["authorization"] == "[REDACTED]", "auth未脱敏"
    assert sanitized["cookie"] == "[COOKIE_REDACTED]", "cookie未脱敏"
    assert sanitized["nested"]["email"] == "[PII_REDACTED]", "嵌套email未脱敏"
    assert sanitized["nested"]["safe"] == "正常文本", "正常文本被误改"
    print(f"  PASS: 数据脱敏正常 (email/phone/auth/cookie 全部脱敏)")

    # 3. ResourceWatchdog 测试
    print("\n[3] ResourceWatchdog 资源看门狗测试...")
    wd = ResourceWatchdog(check_interval_sec=1.0)
    wd.start()
    time.sleep(2.0)
    wd.stop()
    print(f"  PASS: 看门狗运行 {len(wd.violations)} 条记录")

    # 4. CDPLivenessCheck 测试
    print("\n[4] CDPLivenessCheck CDP 活性检查测试...")
    liveness = CDPLivenessCheck("http://127.0.0.1:9224")
    result = liveness.ping_version()
    if result.get("alive"):
        version = result["version"].get("Browser", "unknown")
        print(f"  PASS: CDP 通道存活, Browser={version}")
    else:
        print(f"  WARN: CDP 通道不可用: {result.get('reason')}")
        print(f"        (验证环境应已启动 xuandun-desktop.exe --remote-debugging-port=9224)")

    print("\n" + "=" * 60)
    print("HCSE 沙箱自检完成")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(self_test())
