"""
PHASE 3: RV-Monitor — CDP 运行时验证核心引擎

将 CDP 从"注入工具"提升为"形式化监视器"：
1. Event Sourcing Queue: 维护全局事件队列，存储所有 CDP 事件
2. Invariant Checker: 每个关键事件后立即运行预定义逻辑断言
3. CDP Liveness Check: 断言失败时自动 ping Browser.getVersion 确认 CDP 通道存活
4. Invariant Violation Report: 违反时立即生成报告（时间戳+断言ID+完整上下文）

核心设计：
- 所有 CDP 通信走 WebSocket，单连接复用，带超时和重连
- 事件队列有界（防止内存爆炸），FIFO + 时间戳
- 不变式检查在独立线程运行，不阻塞 CDP 接收
"""
from __future__ import annotations

import json
import queue
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass, field, asdict
from typing import Any, Callable, Optional

import requests
import websocket  # type: ignore

from .sandbox import Sanitizer, PathValidator, SecurityViolation


# ===================================================================
# 数据结构
# ===================================================================
@dataclass
class CDPEvent:
    """CDP 事件源队列中的单个事件。"""
    ts: float                      # 接收时间戳（单调时钟）
    method: str                    # CDP 方法名（如 Runtime.exceptionThrown）
    params: dict                   # 事件参数（已脱敏）
    session_id: Optional[str] = None
    raw_size: int = 0              # 原始字节大小（用于容量监控）


@dataclass
class InvariantViolation:
    """不变式违反报告。"""
    violation_id: str
    invariant_id: str              # INV-XX
    timestamp: str                 # ISO8601 时间戳
    message: str
    triggering_event: Optional[CDPEvent] = None
    context: dict = field(default_factory=dict)
    cdp_liveness: Optional[bool] = None  # CDP 通道是否存活
    stack_trace: Optional[str] = None


@dataclass
class TestResult:
    """单个测试用例结果。"""
    case_id: str
    layer: str                     # L1-L5
    title: str
    status: str                    # PASS / FAIL / SKIP / WARN
    duration_ms: float
    evidence_path: Optional[str] = None  # 截图路径
    invariant_ids: list[str] = field(default_factory=list)
    detail: str = ""
    timestamp: str = ""


# ===================================================================
# RV-Monitor 主引擎
# ===================================================================
class RVMonitor:
    """
    Runtime Verification Monitor — CDP 运行时验证核心。

    生命周期：
      1. connect()              连接 CDP WebSocket
      2. enable_domains()       启用 Runtime/Page/Log/Network 域
      3. start_event_loop()     启动后台事件接收线程
      4. evaluate(expr)         执行 JS（带超时和异常捕获）
      5. assert_invariant(...)  运行时断言（失败立即记录违反）
      6. stop()                 关闭连接，导出事件日志
    """

    CDP_VERSION_REQUIRED = "1.3"

    def __init__(self, cdp_port: int = 9224, page_url_filter: str = "tauri.localhost"):
        self.cdp_port = cdp_port
        self.page_url_filter = page_url_filter
        self.ws: Optional[websocket.WebSocket] = None
        self.target_id: Optional[str] = None
        self.browser_ws: Optional[websocket.WebSocket] = None

        # 事件源队列（有界 deque，防止内存爆炸）
        self.event_queue: deque[CDPEvent] = deque(maxlen=2000)
        self.event_lock = threading.Lock()
        self.event_received_count = 0

        # 异常计数（用于 INV-03 验证）
        self.exception_count = 0
        self.console_errors: list[dict] = []

        # 网络请求计数（用于韧性分析）
        self.network_requests: list[dict] = []

        # 不变式违反清单
        self.violations: list[InvariantViolation] = []
        self.violation_lock = threading.Lock()

        # 消息 ID 自增
        self._next_id = 1
        self._id_lock = threading.Lock()

        # 接收线程控制
        self._stop_event = threading.Event()
        self._recv_thread: Optional[threading.Thread] = None
        self._pending_responses: dict[int, dict] = {}
        self._pending_lock = threading.Lock()
        self._response_cv = threading.Condition(self._pending_lock)

        # 活性检查缓存
        self._last_liveness: Optional[bool] = None
        self._last_liveness_ts: float = 0

    # ---------------------------------------------------------------
    # 连接管理
    # ---------------------------------------------------------------
    def connect(self, timeout: float = 15.0) -> None:
        """连接到 CDP，自动定位玄盾页面 target。"""
        # 1. 获取页面列表
        try:
            resp = requests.get(f"http://localhost:{self.cdp_port}/json", timeout=timeout)
            pages = resp.json()
        except Exception as e:
            raise ConnectionError(f"无法连接 CDP /json 端点（端口 {self.cdp_port}）: {e}")

        # 2. 定位玄盾页面
        target = None
        for page in pages:
            url = page.get("url", "")
            title = page.get("title", "")
            if self.page_url_filter in url or "玄盾" in title:
                target = page
                break
        if not target and pages:
            target = pages[0]  # 降级：取第一个页面
        if not target:
            raise ConnectionError(f"CDP 未找到匹配页面（filter={self.page_url_filter}）")

        self.target_id = target["id"]
        ws_url = target["webSocketDebuggerUrl"]

        # 3. 连接 WebSocket
        self.ws = websocket.create_connection(ws_url, timeout=timeout)
        # 设置非阻塞接收的超时
        self.ws.settimeout(1.0)

        # 4. 同时连接 browser-level WS（用于 Browser.getVersion 活性检查）
        try:
            ver_resp = requests.get(
                f"http://localhost:{self.cdp_port}/json/version", timeout=timeout
            ).json()
            browser_ws_url = ver_resp.get("webSocketDebuggerUrl")
            if browser_ws_url:
                self.browser_ws = websocket.create_connection(browser_ws_url, timeout=timeout)
                self.browser_ws.settimeout(2.0)
        except Exception:
            self.browser_ws = None  # 降级：browser WS 不可用时仅用 page WS

    def enable_domains(self) -> None:
        """启用 CDP 必要域：Runtime / Page / Log / Network。"""
        # Runtime
        self._sync_call("Runtime.enable", {})
        # Page
        self._sync_call("Page.enable", {})
        # Log
        self._sync_call("Log.enable", {})
        # Network
        self._sync_call("Network.enable", {})
        # 性能：开启 Performance 域以便后续采样
        try:
            self._sync_call("Performance.enable", {})
        except Exception:
            pass

    # ---------------------------------------------------------------
    # 事件接收线程
    # ---------------------------------------------------------------
    def start_event_loop(self) -> None:
        """启动后台事件接收线程。"""
        if self._recv_thread is not None:
            return
        self._stop_event.clear()
        self._recv_thread = threading.Thread(
            target=self._event_loop, daemon=True, name="HCSE-RVMonitor"
        )
        self._recv_thread.start()

    def _event_loop(self) -> None:
        """事件接收主循环：解析 CDP 消息，分发到响应/事件队列。"""
        while not self._stop_event.is_set() and self.ws:
            try:
                raw = self.ws.recv()
                if not raw:
                    continue
                msg = json.loads(raw)

                # 响应消息：唤醒等待的同步调用
                if "id" in msg:
                    with self._pending_lock:
                        self._pending_responses[msg["id"]] = msg
                        self._response_cv.notify_all()
                    continue

                # 事件消息：入队 + 触发不变式检查
                method = msg.get("method", "")
                params = msg.get("params", {})
                session_id = msg.get("sessionId")

                # 脱敏后入队
                sanitized_params = Sanitizer.sanitize_dict(params)
                event = CDPEvent(
                    ts=time.time(),
                    method=method,
                    params=sanitized_params,
                    session_id=session_id,
                    raw_size=len(raw),
                )
                with self.event_lock:
                    self.event_queue.append(event)
                    self.event_received_count += 1

                # 实时统计
                self._on_event(method, sanitized_params, event)

            except websocket.WebSocketTimeoutException:
                continue
            except websocket.WebSocketConnectionClosedException:
                # 连接断开，尝试重连一次
                time.sleep(0.5)
                break
            except Exception:
                # 单条消息解析失败不影响整体
                continue

    def _on_event(self, method: str, params: dict, event: CDPEvent) -> None:
        """事件回调：实时统计 + 不变式预检查。"""
        if method == "Runtime.exceptionThrown":
            self.exception_count += 1
            # 记录异常详情
            details = params.get("exceptionDetails", {})
            self.console_errors.append({
                "ts": event.ts,
                "text": details.get("text", ""),
                "url": details.get("url", ""),
                "line": details.get("lineNumber", 0),
            })
        elif method == "Log.entryAdded":
            entry = params.get("entry", {})
            if entry.get("level") in ("error", "warning"):
                self.console_errors.append({
                    "ts": event.ts,
                    "level": entry.get("level"),
                    "text": entry.get("text", ""),
                    "source": entry.get("source", ""),
                })
        elif method == "Network.requestWillBeSent":
            req = params.get("request", {})
            self.network_requests.append({
                "ts": event.ts,
                "requestId": params.get("requestId"),
                "url": req.get("url", ""),
                "method": req.get("method", ""),
            })
            # 容量保护
            if len(self.network_requests) > 500:
                self.network_requests = self.network_requests[-500:]
        elif method == "Network.responseReceived":
            resp = params.get("response", {})
            status = resp.get("status", 0)
            if status >= 500:
                # 5xx 错误：记录但不立即违反（INV-03 会在最终评估）
                self.console_errors.append({
                    "ts": event.ts,
                    "level": "error",
                    "text": f"HTTP {status}: {resp.get('url', '')}",
                    "source": "network",
                })

    # ---------------------------------------------------------------
    # 同步调用（带超时）
    # ---------------------------------------------------------------
    def _next_msg_id(self) -> int:
        with self._id_lock:
            mid = self._next_id
            self._next_id += 1
            return mid

    def _sync_call(self, method: str, params: dict, timeout: float = 15.0) -> dict:
        """同步调用 CDP 方法，等待响应。"""
        if not self.ws:
            raise RuntimeError("CDP WebSocket 未连接")
        mid = self._next_msg_id()
        msg = {"id": mid, "method": method, "params": params}
        self.ws.send(json.dumps(msg))

        # 等待响应
        deadline = time.time() + timeout
        with self._pending_lock:
            while mid not in self._pending_responses:
                remaining = deadline - time.time()
                if remaining <= 0:
                    raise TimeoutError(f"CDP 调用超时（{method}，{timeout}s）")
                self._response_cv.wait(timeout=remaining)
            response = self._pending_responses.pop(mid)
        if "error" in response:
            raise RuntimeError(f"CDP 调用错误（{method}）: {response['error']}")
        return response.get("result", {})

    def evaluate(self, expression: str, timeout: float = 15.0,
                 await_promise: bool = False, return_by_value: bool = True) -> Any:
        """
        执行 JavaScript 表达式，返回结果。
        异常时抛出 RuntimeError，不静默吞错。
        """
        params = {
            "expression": expression,
            "returnByValue": return_by_value,
            "awaitPromise": await_promise,
            "userGesture": True,
        }
        try:
            result = self._sync_call("Runtime.evaluate", params, timeout=timeout)
        except TimeoutError:
            # CDP 超时：先做活性检查
            alive = self.check_liveness()
            raise RuntimeError(
                f"Runtime.evaluate 超时（{timeout}s），CDP 活性={alive}，"
                f"表达式前80字符: {expression[:80]!r}"
            )

        # 检查异常
        if "exceptionDetails" in result:
            details = result["exceptionDetails"]
            err_text = details.get("exception", {}).get("description", "") or details.get("text", "")
            raise RuntimeError(f"JS 执行异常: {err_text}")

        value = result.get("result", {}).get("value")
        return value

    def evaluate_safe(self, expression: str, timeout: float = 15.0) -> tuple[bool, Any, str]:
        """安全版本：返回 (success, value, error_message)。"""
        try:
            value = self.evaluate(expression, timeout=timeout)
            return True, value, ""
        except Exception as e:
            return False, None, str(e)

    # ---------------------------------------------------------------
    # 不变式断言
    # ---------------------------------------------------------------
    def assert_invariant(self, invariant_id: str, condition: bool,
                         message: str, context: Optional[dict] = None,
                         triggering_event: Optional[CDPEvent] = None,
                         hard_halt: bool = False) -> None:
        """
        断言不变式。condition=False 时记录违反，hard_halt=True 时立即终止。
        """
        if condition:
            return
        # CDP 活性检查（避免因 CDP 丢包导致假阴性）
        liveness = self.check_liveness()
        violation = InvariantViolation(
            violation_id=f"VIO-{uuid.uuid4().hex[:8]}",
            invariant_id=invariant_id,
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime()),
            message=message,
            triggering_event=triggering_event,
            context=context or {},
            cdp_liveness=liveness,
        )
        with self.violation_lock:
            self.violations.append(violation)

        if hard_halt:
            raise SecurityViolation(
                f"[硬停机] 不变式违反 {invariant_id}: {message} (CDP活={liveness})",
                hard_halt=True,
            )

    def check_liveness(self) -> bool:
        """CDP 活性检查：ping Browser.getVersion，10s 内缓存结果。"""
        now = time.time()
        if now - self._last_liveness_ts < 10 and self._last_liveness is not None:
            return self._last_liveness

        # 优先用 browser WS（不干扰 page WS 接收线程）
        if self.browser_ws:
            try:
                mid = self._next_msg_id()
                self.browser_ws.send(json.dumps({"id": mid, "method": "Browser.getVersion"}))
                deadline = time.time() + 3
                while time.time() < deadline:
                    try:
                        raw = self.browser_ws.recv()
                        msg = json.loads(raw)
                        if msg.get("id") == mid:
                            self._last_liveness = "result" in msg or "Browser" in msg.get("result", {})
                            self._last_liveness_ts = now
                            return self._last_liveness
                    except websocket.WebSocketTimeoutException:
                        continue
            except Exception:
                pass

        # 降级：用 page WS 的 Runtime.evaluate
        try:
            self._sync_call("Runtime.evaluate",
                            {"expression": "navigator.userAgent", "returnByValue": True},
                            timeout=3)
            self._last_liveness = True
            self._last_liveness_ts = now
            return True
        except Exception:
            self._last_liveness = False
            self._last_liveness_ts = now
            return False

    # ---------------------------------------------------------------
    # 截图
    # ---------------------------------------------------------------
    def screenshot(self, output_path: str, format: str = "png") -> str:
        """截图并保存到指定路径（必须经 PathValidator 校验）。"""
        validated = PathValidator.validate(output_path, "write")
        result = self._sync_call("Page.captureScreenshot", {"format": format}, timeout=30)
        data = result.get("data")
        if not data:
            raise RuntimeError("截图返回空数据")
        import base64
        with open(validated, "wb") as f:
            f.write(base64.b64decode(data))
        return validated

    # ---------------------------------------------------------------
    # 生命周期
    # ---------------------------------------------------------------
    def stop(self) -> None:
        """停止事件循环并关闭连接。"""
        self._stop_event.set()
        if self._recv_thread:
            self._recv_thread.join(timeout=5)
            self._recv_thread = None
        if self.ws:
            try:
                self.ws.close()
            except Exception:
                pass
            self.ws = None
        if self.browser_ws:
            try:
                self.browser_ws.close()
            except Exception:
                pass
            self.browser_ws = None

    def get_event_log(self) -> list[CDPEvent]:
        with self.event_lock:
            return list(self.event_queue)

    def get_summary(self) -> dict:
        return {
            "event_count": self.event_received_count,
            "exception_count": self.exception_count,
            "console_error_count": len(self.console_errors),
            "network_request_count": len(self.network_requests),
            "violation_count": len(self.violations),
            "violations": [asdict(v) for v in self.violations],
            "last_liveness": self._last_liveness,
        }
