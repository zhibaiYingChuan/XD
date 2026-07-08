import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

import numpy as np
from daoti_xuandun.dynamic_shell import DynamicShell, _chaotic_series
from daoti_xuandun.config import XuanDunConfig, DefenseLevel
from daoti_xuandun.xuandun import XuanDun

def test_dynamic_shell_session_isolation():
    print("=" * 60)
    print("  测试1: 动态阴阳壳会话隔离")
    print("=" * 60)
    
    config = XuanDunConfig.preset(DefenseLevel.STANDARD)
    shell = DynamicShell(config)
    
    rng = np.random.default_rng(42)
    test_input = rng.normal(0, 1, config.hidden_dim).astype(np.float32)
    
    num_sessions = 5
    num_calls = 10
    session_outputs = {}
    
    for sid in range(num_sessions):
        session_key = shell._session_seed(f"session_{sid}")
        outputs = []
        for c in range(num_calls):
            out = shell.transform(test_input.copy(), session_id=f"session_{sid}")
            outputs.append(out.copy())
        session_outputs[sid] = np.mean(outputs, axis=0)
    
    means = list(session_outputs.values())
    similarities = []
    for i in range(len(means)):
        for j in range(i + 1, len(means)):
            sim = np.dot(means[i], means[j]) / (
                np.linalg.norm(means[i]) * np.linalg.norm(means[j]) + 1e-12
            )
            similarities.append(float(sim))
            print(f"  session_{i} vs session_{j}: cosine_similarity = {sim:.6f}")
    
    mean_sim = float(np.mean(similarities))
    max_sim = float(np.max(similarities))
    
    print(f"\n  跨会话平均相似度: {mean_sim:.6f}")
    print(f"  跨会话最大相似度: {max_sim:.6f}")
    print(f"  隔离判定 (|mean_sim| < 0.9): {'通过' if abs(mean_sim) < 0.9 else '失败'}")
    
    return abs(mean_sim) < 0.9


def test_xuandun_session_isolation():
    print("\n" + "=" * 60)
    print("  测试2: XuanDun全链路会话隔离")
    print("=" * 60)
    
    config = XuanDunConfig.preset(DefenseLevel.STANDARD)
    xuandun = XuanDun(config)
    xuandun.seed([
        "论语有云学而时习之不亦说乎",
        "道德经曰道可道非常道名可名非常名",
    ])
    
    test_input = "测试会话隔离性"
    num_sessions = 5
    num_calls = 10
    session_outputs = {}
    
    for sid in range(num_sessions):
        outputs = []
        for c in range(num_calls):
            r = xuandun.protect(test_input, session_id=f"session_iso_{sid}")
            if r.final_output is not None:
                outputs.append(np.array(r.final_output))
        if outputs:
            session_outputs[sid] = np.mean(outputs, axis=0)
    
    if len(session_outputs) < 2:
        print("  错误: 会话输出不足")
        return False
    
    means = list(session_outputs.values())
    similarities = []
    for i in range(len(means)):
        for j in range(i + 1, len(means)):
            sim = np.dot(means[i], means[j]) / (
                np.linalg.norm(means[i]) * np.linalg.norm(means[j]) + 1e-12
            )
            similarities.append(float(sim))
            print(f"  session_{i} vs session_{j}: cosine_similarity = {sim:.6f}")
    
    mean_sim = float(np.mean(similarities))
    max_sim = float(np.max(similarities))
    
    print(f"\n  跨会话平均相似度: {mean_sim:.6f}")
    print(f"  跨会话最大相似度: {max_sim:.6f}")
    print(f"  隔离判定 (|mean_sim| < 0.9): {'通过' if abs(mean_sim) < 0.9 else '失败'}")
    
    return abs(mean_sim) < 0.9


def test_same_session_consistency():
    print("\n" + "=" * 60)
    print("  测试3: 同一会话内一致性（相同输入应产生相同输出）")
    print("=" * 60)
    
    config = XuanDunConfig.preset(DefenseLevel.STANDARD)
    shell = DynamicShell(config)
    
    rng = np.random.default_rng(123)
    test_input = rng.normal(0, 1, config.hidden_dim).astype(np.float32)
    
    outputs = []
    for c in range(5):
        shell_fresh = DynamicShell(config)
        out = shell_fresh.transform(test_input.copy(), session_id="same_session")
        outputs.append(out.copy())
    
    for i in range(1, len(outputs)):
        diff = np.linalg.norm(outputs[0] - outputs[i])
        print(f"  call_0 vs call_{i}: L2距离 = {diff:.6f}")
    
    return True


if __name__ == "__main__":
    results = []
    
    r1 = test_dynamic_shell_session_isolation()
    results.append(("动态壳会话隔离", r1))
    
    r2 = test_xuandun_session_isolation()
    results.append(("全链路会话隔离", r2))
    
    r3 = test_same_session_consistency()
    results.append(("同一会话一致性", r3))
    
    print("\n" + "=" * 60)
    print("  会话隔离验证总结")
    print("=" * 60)
    for name, passed in results:
        status = "通过" if passed else "失败"
        print(f"  {name}: {status}")
    
    all_passed = all(r for _, r in results)
    print(f"\n  总体: {'全部通过' if all_passed else '存在失败项'}")
