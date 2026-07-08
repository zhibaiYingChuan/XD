"""快速检查 Python 环境和依赖"""
import sys
import os

output = []
output.append(f"Python: {sys.version}")
output.append(f"Python path: {sys.executable}")
output.append(f"CWD: {os.getcwd()}")

try:
    import flask
    output.append(f"Flask: {flask.__version__}")
except ImportError:
    output.append("Flask: NOT INSTALLED")

try:
    import numpy
    output.append(f"NumPy: {numpy.__version__}")
except ImportError:
    output.append("NumPy: NOT INSTALLED")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))
try:
    from daoti_xuandun import XuanDun, XuanDunConfig, DefenseLevel
    output.append("daoti_xuandun: OK")

    config = XuanDunConfig.for_level(DefenseLevel.STANDARD)
    shield = XuanDun(config)
    result = shield.protect("Hello world", session_id="env-test")
    output.append(f"protect() test: allowed={result.allowed}, trust_level={result.trust_level}")

    import time
    lats = []
    for i in range(5):
        t0 = time.perf_counter()
        shield.protect(f"Test {i}", session_id=f"bench-{i}")
        lats.append((time.perf_counter() - t0) * 1000)
    avg = sum(lats) / len(lats)
    output.append(f"Core latency (5 runs): avg={avg:.1f}ms, min={min(lats):.1f}ms, max={max(lats):.1f}ms")
except Exception as e:
    output.append(f"daoti_xuandun: FAILED - {e}")

result_file = os.path.join(os.path.dirname(__file__), "env_check_result.txt")
with open(result_file, "w", encoding="utf-8") as f:
    f.write("\n".join(output))

print("\n".join(output))
