from daoti_xuandun import XuanDun, XuanDunConfig, DefenseLevel
import numpy as np

cfg = XuanDunConfig.preset(DefenseLevel.STANDARD)
xd = XuanDun(cfg)
xd.seed([
    '论语有云学而时习之不亦说乎',
    '道德经曰道可道非常道名可名非常名',
    '黄帝内经曰上古之人春秋皆度百岁',
    '孙子曰兵者诡道也故能而示之不能',
    '周易曰天行健君子以自强不息',
    '孟子曰民为贵社稷次之君为轻',
    '诗经云关关雎鸠在河之洲',
    '礼记曰大道之行也天下为公',
    '论语曰三人行必有我师焉',
    '道德经曰上善若水水善利万物而不争',
    '学而不思则罔思而不学则殆',
    '己所不欲勿施于人',
])

warmup = [
    "论语有云学而时习之", "道德经曰道可道", "黄帝内经曰上古之人",
    "孙子曰兵者诡道也", "周易曰天行健", "孟子曰民为贵",
    "诗经云关关雎鸠", "礼记曰大道之行也",
]
for i, t in enumerate(warmup):
    xd.protect(t, session_id=f'w_{i}')

test_input = "测试会话隔离性"
outputs_by_session = {}

for sid in range(3):
    outputs = []
    for c in range(5):
        r = xd.protect(test_input, session_id=f"iso_{sid}_{c}")
        print(f"  sid={sid}_{c}: allowed={r.allowed}, trust={r.trust_level}, final_output={'None' if r.final_output is None else f'len={len(r.final_output)}'}")
        if r.final_output is not None:
            v = np.array(r.final_output)
            outputs.append(v)
    if outputs:
        mean_v = np.mean(outputs, axis=0)
        outputs_by_session[sid] = mean_v

if len(outputs_by_session) >= 2:
    print("\nPairwise similarities:")
    keys = list(outputs_by_session.keys())
    for i in range(len(keys)):
        for j in range(i+1, len(keys)):
            vi = outputs_by_session[keys[i]]
            vj = outputs_by_session[keys[j]]
            sim = np.dot(vi, vj) / (np.linalg.norm(vi) * np.linalg.norm(vj) + 1e-12)
            print(f"  Session {keys[i]} vs {keys[j]}: cos_sim={sim:.4f}")
else:
    print(f"\nNot enough sessions with outputs: {len(outputs_by_session)}")