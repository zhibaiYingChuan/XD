import sys, time, statistics
sys.path.insert(0, "e:/smallloong/XuanDun/src")
from daoti_xuandun.mcp_server import _handle_tools_call

lats = []
for i in range(10):
    t0 = time.perf_counter()
    _handle_tools_call({"name": "xuandun_protect", "arguments": {"text": f"Test {i}"}})
    lats.append((time.perf_counter() - t0) * 1000)

print(f"MCP avg: {statistics.mean(lats):.1f}ms")
print(f"MCP med: {statistics.median(lats):.1f}ms")
print(f"MCP p99: {sorted(lats)[9]:.1f}ms")
