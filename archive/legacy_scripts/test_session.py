from daoti_xuandun import XuanDun, XuanDunConfig, DefenseLevel
import numpy as np

cfg = XuanDunConfig.preset(DefenseLevel.STANDARD)
xd = XuanDun(cfg)

test_input = "测试会话隔离性"
outputs_by_session = {}

for sid in range(3):
    outputs = []
    for c in range(5):
        r = xd.protect(test_input, session_id=f"iso_{sid}_{c}")
        if r.final_output is not None:
            v = np.array(r.final_output)
            outputs.append(v)
            if sid == 0 and c < 2:
                print(f"Session {sid}_{c}: output[:5]={v[:5]}, norm={np.linalg.norm(v):.4f}")
    if outputs:
        mean_v = np.mean(outputs, axis=0)
        outputs_by_session[sid] = mean_v
        print(f"Session {sid} mean: norm={np.linalg.norm(mean_v):.4f}, mean[:5]={mean_v[:5]}")

print("\nPairwise similarities:")
for i in range(len(outputs_by_session)):
    for j in range(i+1, len(outputs_by_session)):
        vi = outputs_by_session[i]
        vj = outputs_by_session[j]
        sim = np.dot(vi, vj) / (np.linalg.norm(vi) * np.linalg.norm(vj) + 1e-12)
        print(f"  Session {i} vs {j}: cos_sim={sim:.4f}")

print("\n--- Direct transform test ---")
from daoti_xuandun.dynamic_shell import DynamicShell
shell = DynamicShell(cfg)
x = np.random.randn(cfg.hidden_dim).astype(np.float32)
x = x / np.linalg.norm(x)

out1 = shell.transform(x, session_id="session_A")
out2 = shell.transform(x, session_id="session_B")
sim = np.dot(out1, out2) / (np.linalg.norm(out1) * np.linalg.norm(out2) + 1e-12)
print(f"Direct transform: session_A vs session_B cos_sim={sim:.4f}")
print(f"  out1[:5]={out1[:5]}")
print(f"  out2[:5]={out2[:5]}")