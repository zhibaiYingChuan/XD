import time
from daoti_xuandun import XuanDun, XuanDunConfig, DefenseLevel

print("Creating XuanDun STANDARD...")
s = time.perf_counter()
shield = XuanDun(XuanDunConfig.for_level(DefenseLevel.STANDARD))
print("Init: %.1fms" % ((time.perf_counter()-s)*1000))

print("Testing protect()...")
for i in range(5):
    s = time.perf_counter()
    result = shield.protect("Hello world", session_id="test%d" % i)
    lat = (time.perf_counter()-s)*1000
    print("  req %d: %.1fms allowed=%s trust=%s" % (i, lat, result.allowed, result.trust_level))
