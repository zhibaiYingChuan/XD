import time
from daoti_xuandun import XuanDun, XuanDunConfig, DefenseLevel

lines = []
s = time.perf_counter()
config = XuanDunConfig.for_level(DefenseLevel.STANDARD)
config.enable_imperative_whitelist = False
shield = XuanDun(config)
lines.append("Init: %.1fms" % ((time.perf_counter()-s)*1000))

for i in range(3):
    s = time.perf_counter()
    result = shield.protect("Hello world", session_id="test%d" % i)
    lat = (time.perf_counter()-s)*1000
    lines.append("req %d: %.1fms allowed=%s trust=%s" % (i, lat, result.allowed, result.trust_level))

with open("test_no_whitelist.txt", "w") as f:
    f.write("\n".join(lines))
