import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))
try:
    from daoti_xuandun import XuanDun, XuanDunConfig, DefenseLevel
    r = XuanDun(XuanDunConfig.for_level(DefenseLevel.STANDARD)).protect("Hello", session_id="t")
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "quick_test.txt"), "w") as f:
        f.write(f"OK: allowed={r.allowed} trust={r.trust_level}\n")
except Exception as e:
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "quick_test.txt"), "w") as f:
        f.write(f"FAIL: {e}\n")
