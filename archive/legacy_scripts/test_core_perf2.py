import time
from daoti_xuandun import XuanDun, XuanDunConfig, DefenseLevel

lines = []
s = time.perf_counter()
shield = XuanDun(XuanDunConfig.for_level(DefenseLevel.STANDARD))
lines.append("Init: %.1fms" % ((time.perf_counter()-s)*1000))

for i in range(5):
    s = time.perf_counter()
    result = shield.protect("Hello world", session_id="test%d" % i)
    lat = (time.perf_counter()-s)*1000
    lines.append("req %d: %.1fms allowed=%s trust=%s" % (i, lat, result.allowed, result.trust_level))

with open("test_core_perf_out.txt", "w") as f:
    f.write("\n".join(lines))
