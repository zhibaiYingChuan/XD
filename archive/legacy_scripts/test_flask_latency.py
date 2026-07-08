"""自包含测试脚本 - 测试 Flask 引擎延迟并写入结果文件"""
import sys
import os
import time
import json
import statistics
import urllib.request
import urllib.error

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

RESULT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "flask_test_result.txt")
lines = []


def log(msg):
    lines.append(msg)
    print(msg, flush=True)


def _req(url, data=None, method="GET", timeout=10):
    if data is not None:
        body = json.dumps(data).encode("utf-8")
    else:
        body = None
    req = urllib.request.Request(url, data=body, method=method)
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8")), resp.status
    except urllib.error.HTTPError as e:
        body_text = e.read().decode("utf-8", errors="replace")
        try:
            return json.loads(body_text), e.code
        except json.JSONDecodeError:
            return {"raw": body_text}, e.code
    except Exception as e:
        return {"error": str(e)}, 0


def main():
    log("=" * 60)
    log("  Flask 引擎延迟测试")
    log("=" * 60)

    log("\n--- 1. 核心库基准 ---")
    try:
        from daoti_xuandun import XuanDun, XuanDunConfig, DefenseLevel
        config = XuanDunConfig.for_level(DefenseLevel.STANDARD)
        shield = XuanDun(config)

        lats = []
        for i in range(20):
            t0 = time.perf_counter()
            shield.protect(f"Test {i}", session_id=f"bench-{i}")
            lats.append((time.perf_counter() - t0) * 1000)
        avg = statistics.mean(lats)
        med = statistics.median(lats)
        p99 = sorted(lats)[int(len(lats) * 0.99)]
        log(f"  核心: avg={avg:.1f}ms med={med:.1f}ms p99={p99:.1f}ms")
        log(f"  核心 avg < 20ms: {'PASS' if avg < 20 else 'FAIL'}")
    except Exception as e:
        log(f"  核心库失败: {e}")

    log("\n--- 2. Flask 引擎 HTTP 延迟 ---")
    FLASK_URL = "http://127.0.0.1:18766"
    try:
        data, code = _req(f"{FLASK_URL}/health", timeout=3)
        if code == 200:
            log(f"  Flask 引擎在线: {data}")
        else:
            log(f"  Flask 引擎异常: code={code}")
    except Exception as e:
        log(f"  Flask 引擎离线: {e}")
        log("  请先启动: python desktop/xuandun-desktop/engine_flask.py --port 18766")

    try:
        data, code = _req(f"{FLASK_URL}/health", timeout=3)
        if code == 200:
            lats = []
            for i in range(20):
                t0 = time.perf_counter()
                data, code = _req(f"{FLASK_URL}/protect", data={"text": f"Test message {i}"}, method="POST")
                lat = (time.perf_counter() - t0) * 1000
                if code == 200:
                    lats.append(lat)
            if lats:
                avg = statistics.mean(lats)
                med = statistics.median(lats)
                p95 = sorted(lats)[int(len(lats) * 0.95)]
                p99 = sorted(lats)[min(int(len(lats) * 0.99), len(lats) - 1)]
                mx = max(lats)
                log(f"  Flask: avg={avg:.1f}ms med={med:.1f}ms p95={p95:.1f}ms p99={p99:.1f}ms max={mx:.1f}ms")
                log(f"  Flask avg < 50ms: {'PASS' if avg < 50 else 'FAIL'}")
                log(f"  Flask p99 < 200ms: {'PASS' if p99 < 200 else 'FAIL'}")
                log(f"  Flask max < 2000ms: {'PASS' if mx < 2000 else 'FAIL'}")
            else:
                log("  Flask: 无成功请求")
    except Exception as e:
        log(f"  Flask 测试失败: {e}")

    log("\n--- 3. HTTP 引擎延迟 (engine_main.py) ---")
    ENGINE_URL = "http://127.0.0.1:18765"
    try:
        data, code = _req(f"{ENGINE_URL}/health", timeout=3)
        if code == 200:
            log(f"  HTTP 引擎在线: {data}")
            lats = []
            for i in range(20):
                t0 = time.perf_counter()
                data, code = _req(f"{ENGINE_URL}/protect", data={"text": f"Test message {i}"}, method="POST")
                lat = (time.perf_counter() - t0) * 1000
                if code == 200:
                    lats.append(lat)
            if lats:
                avg = statistics.mean(lats)
                med = statistics.median(lats)
                p95 = sorted(lats)[int(len(lats) * 0.95)]
                p99 = sorted(lats)[min(int(len(lats) * 0.99), len(lats) - 1)]
                mx = max(lats)
                log(f"  HTTP: avg={avg:.1f}ms med={med:.1f}ms p95={p95:.1f}ms p99={p99:.1f}ms max={mx:.1f}ms")
                log(f"  HTTP avg < 50ms: {'PASS' if avg < 50 else 'FAIL'}")
                log(f"  HTTP p99 < 200ms: {'PASS' if p99 < 200 else 'FAIL'}")
                log(f"  HTTP max < 2000ms: {'PASS' if mx < 2000 else 'FAIL'}")
            else:
                log("  HTTP: 无成功请求")
        else:
            log(f"  HTTP 引擎异常: code={code}")
    except Exception as e:
        log(f"  HTTP 引擎离线: {e}")

    log("\n--- 4. MCP Server 直接调用测试 ---")
    try:
        from daoti_xuandun.mcp_server import _handle_initialize, _handle_tools_list, _handle_tools_call
        result = _handle_initialize({})
        log(f"  MCP init: protocol={result.get('protocolVersion')} server={result.get('serverInfo', {}).get('name')}")

        result = _handle_tools_list({})
        tools = result.get("tools", [])
        tool_names = [t["name"] for t in tools]
        log(f"  MCP tools: {tool_names}")

        lats = []
        for i in range(20):
            t0 = time.perf_counter()
            _handle_tools_call({
                "name": "xuandun_protect",
                "arguments": {"text": f"Test {i}"},
            })
            lats.append((time.perf_counter() - t0) * 1000)
        avg = statistics.mean(lats)
        log(f"  MCP direct: avg={avg:.1f}ms")
        log(f"  MCP avg < 50ms: {'PASS' if avg < 50 else 'FAIL'}")
    except Exception as e:
        log(f"  MCP 测试失败: {e}")

    with open(RESULT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    log(f"\n结果已写入: {RESULT_FILE}")


if __name__ == "__main__":
    main()
