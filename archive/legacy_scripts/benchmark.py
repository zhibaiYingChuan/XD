"""道体·玄盾 性能基准测试脚本。

测试不同配置下的延迟和吞吐量，用于产品定价参考。
"""

import time

import numpy as np

from daoti_xuandun import XuanDun, XuanDunConfig


def benchmark_protect(xd, input_text, session, repeat=100):
    """测试单次 protect 调用的延迟。

    Args:
        xd: XuanDun 实例。
        input_text: 输入文本。
        session: 会话 ID。
        repeat: 重复次数。

    Returns:
        (avg_ms, p95_ms) 平均延迟和 P95 延迟（毫秒）。
    """
    times = []
    for _ in range(repeat):
        start = time.perf_counter()
        _ = xd.protect(input_text, session)
        times.append(time.perf_counter() - start)
    avg_ms = np.mean(times) * 1000
    p95_ms = np.percentile(times, 95) * 1000
    return avg_ms, p95_ms


def benchmark_throughput(xd, input_text, sessions, workers=32, total=5000):
    """测试并发吞吐量。

    Args:
        xd: XuanDun 实例。
        input_text: 输入文本。
        sessions: 会话 ID 列表。
        workers: 并发线程数。
        total: 总请求数。

    Returns:
        QPS（每秒请求数）。
    """
    from concurrent.futures import ThreadPoolExecutor

    def task(i):
        sess = sessions[i % len(sessions)]
        return xd.protect(input_text, sess)

    with ThreadPoolExecutor(max_workers=workers) as ex:
        start = time.perf_counter()
        list(ex.map(task, range(total)))
        elapsed = time.perf_counter() - start
    return total / elapsed


def main():
    print("=" * 60)
    print("  道体·玄盾 性能基准测试")
    print("=" * 60)

    config = XuanDunConfig(
        hidden_dim=128, num_layers=3, t_iter=5, enable_timing_check=True
    )
    xd = XuanDun(config, domain_classifier=None)
    test_input = "What is the meaning of life?"

    print("\n[1] 延迟测试 (100 runs):")
    avg, p95 = benchmark_protect(xd, test_input, "bench_session")
    print(f"    Avg: {avg:.2f} ms, P95: {p95:.2f} ms")

    print("\n[2] 吞吐量测试 (5000 requests, 32 workers):")
    sessions = [f"user_{i}" for i in range(100)]
    qps = benchmark_throughput(xd, test_input, sessions)
    print(f"    QPS: {qps:.1f} req/s")

    print("\n[3] 不同 hidden_dim 性能对比 (50 runs):")
    for dim in [64, 128, 256]:
        config.hidden_dim = dim
        xd2 = XuanDun(config, domain_classifier=None)
        avg2, _ = benchmark_protect(xd2, test_input, "bench", repeat=50)
        print(f"    hidden_dim={dim:>3d}: {avg2:.2f} ms")

    print("\n[4] 不同 t_iter 性能对比 (50 runs):")
    config.hidden_dim = 128
    for t_iter in [1, 3, 5, 10]:
        config.t_iter = t_iter
        xd3 = XuanDun(config, domain_classifier=None)
        avg3, _ = benchmark_protect(xd3, test_input, "bench", repeat=50)
        print(f"    t_iter={t_iter:>2d}: {avg3:.2f} ms")

    print("\n[5] 模块开关性能对比 (50 runs):")
    combos = {
        "全启用": XuanDunConfig(hidden_dim=128, t_iter=3),
        "无门禁": XuanDunConfig(hidden_dim=128, t_iter=3, enable_reject_gate=False),
        "无阴阳壳": XuanDunConfig(hidden_dim=128, t_iter=3, enable_dynamic_shell=False),
        "无时序": XuanDunConfig(hidden_dim=128, t_iter=3, enable_timing_check=False),
        "全禁用": XuanDunConfig(
            hidden_dim=128,
            enable_reject_gate=False,
            enable_dynamic_shell=False,
            enable_ancient_map=False,
            enable_timing_check=False,
        ),
    }
    for name, cfg in combos.items():
        xd4 = XuanDun(cfg, domain_classifier=None)
        avg4, _ = benchmark_protect(xd4, test_input, "bench", repeat=50)
        print(f"    {name}: {avg4:.2f} ms")

    print("\n" + "=" * 60)
    print("  基准测试完成")
    print("=" * 60)


if __name__ == "__main__":
    main()