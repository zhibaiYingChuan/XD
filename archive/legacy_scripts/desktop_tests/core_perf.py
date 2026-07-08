import time, sys
sys.path.insert(0, "../../src")
from daoti_xuandun import XuanDun, XuanDunConfig, DefenseLevel

print("Creating XuanDun instance...")
s = time.perf_counter()
shield = XuanDun(XuanDunConfig.for_level(DefenseLevel.STANDARD))
print("  Init: %.1fms" % ((time.perf_counter()-s)*1000))

print("\nTesting protect()...")
lats = []
for i in range(10):
    s = time.perf_counter()
    result = shield.protect("Write a Python function to sort a list", session_id="test")
    lat = (time.perf_counter()-s)*1000
    lats.append(lat)
    print("  req %d: %.1fms allowed=%s trust=%s" % (i, lat, result.allowed, result.trust_level))

avg = sum(lats)/len(lats)
p99 = sorted(lats)[9]
print("\navg=%.1fms p99=%.1fms" % (avg, p99))
