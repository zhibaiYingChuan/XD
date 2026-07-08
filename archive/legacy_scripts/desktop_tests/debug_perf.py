import time, sys
sys.path.insert(0, "../../src")
from daoti_xuandun import XuanDun, XuanDunConfig, DefenseLevel

print("Creating XuanDun...")
s = time.perf_counter()
shield = XuanDun(XuanDunConfig.for_level(DefenseLevel.STANDARD))
print("Init: %.1fms" % ((time.perf_counter()-s)*1000))

print("\nTesting domain_awareness.process() directly...")
da = shield.domain_awareness
for i in range(5):
    s = time.perf_counter()
    decision, vec, trust, dist = da.process("Hello world", "test")
    lat = (time.perf_counter()-s)*1000
    print("  da.process %d: %.1fms decision=%s trust=%s" % (i, lat, decision, trust))

print("\nTesting full protect()...")
for i in range(5):
    s = time.perf_counter()
    result = shield.protect("Hello world", session_id="test")
    lat = (time.perf_counter()-s)*1000
    print("  protect %d: %.1fms allowed=%s trust=%s" % (i, lat, result.allowed, result.trust_level))
