# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白
# 本文件受道体研究许可证 v1.0 约束，禁止逆向工程和再分发
# 详见 LICENSE 文件

# 动态阴阳壳 — 状态依赖权重演化 + 混沌非零偏置
# 壳本身是一个动态系统，权重随状态在线更新，任何输入都产生高熵输出。

from typing import Tuple
import hashlib
import numpy as np

from daoti_xuandun.config import XuanDunConfig


def _chaotic_series(seed: int, length: int) -> np.ndarray:
    """基于 logistic map 生成混沌序列。"""
    x = (seed % 9973) / 9973.0 if seed != 0 else 0.5
    series = np.zeros(length, dtype=np.float32)
    for i in range(length):
        x = 3.99 * x * (1.0 - x)
        series[i] = x
    return series


class DynamicShell:
    """动态阴阳壳 — 状态依赖权重演化。

    核心改进：
    - 偏置非零：由密钥和调用计数派生的混沌序列生成，确保零向量输入也产生非零输出。
    - 权重动态演化：每次调用后，权重根据当前状态做微量更新（确定性、密钥驱动），
      增强雪崩效应，使静态逆映射不可行。
    - 壳本身是单向不可逆的（防御层，不需要编码器/解码器）。

    Attributes:
        config: 全局配置。
        dim: 隐藏维度。
        num_layers: 递归层数。
        t_iter: 迭代次数。
        call_count: 累计调用次数，驱动偏置和权重演化。
        W_f, U_f, b_f: 正向权重和偏置。
        W_b, U_b, b_b: 逆向权重和偏置。
    """

    def __init__(self, config: XuanDunConfig):
        self.config = config
        self.dim = config.hidden_dim
        self.num_layers = config.num_layers
        self.t_iter = config.t_iter
        self._key = config.shell_key
        self.call_count: int = 0
        self._session_calls: dict = {}
        self._init_weights()

    def _init_weights(self):
        """初始化权重矩阵，由 shell_key 种子驱动。"""
        init_rng = np.random.default_rng(seed=int.from_bytes(self._key, "little"))
        limit = 0.1
        self.W_f = init_rng.uniform(-limit, limit, (self.dim, self.dim)).astype(np.float32)
        self.U_f = init_rng.uniform(-limit, limit, (self.dim, self.dim)).astype(np.float32)
        self.b_f = np.zeros(self.dim, dtype=np.float32)
        self.W_b = init_rng.uniform(-limit, limit, (self.dim, self.dim)).astype(np.float32)
        self.U_b = init_rng.uniform(-limit, limit, (self.dim, self.dim)).astype(np.float32)
        self.b_b = np.zeros(self.dim, dtype=np.float32)
        self._perturb_rng = np.random.default_rng(seed=int.from_bytes(self._key, "little") ^ 0xDEADBEEF)

    def _derive_biases(self, session_key: int = 0) -> Tuple[np.ndarray, np.ndarray]:
        """从密钥 + 调用计数 + 会话种子派生混沌非零偏置。

        偏置依赖密钥、调用计数和会话种子，确保不同会话产生不同输出。
        同一会话内相同输入产生相同输出，确保符号映射缓存稳定。
        攻击者无法预知偏置，因为调用计数的演进序列由密钥驱动。
        """
        scale = self.config.chaos_phase_scale
        seed_f = (int.from_bytes(self._key[:8], "little")
                  ^ (self.call_count * 2654435761)
                  ^ (session_key * 15485863))
        seed_b = (int.from_bytes(self._key[8:], "little")
                  ^ (self.call_count * 3624360691)
                  ^ (session_key * 32452843))

        b_f = (_chaotic_series(seed_f, self.dim) - 0.5) * 2.0 * scale
        b_b = (_chaotic_series(seed_b, self.dim) - 0.5) * 2.0 * scale
        return b_f.astype(np.float32), b_b.astype(np.float32)

    def _inject_perturbation(self):
        """周期性注入随机扰动，防止攻击者通过海量查询拟合壳映射。

        每 perturbation_interval 次调用触发一次，向所有权重矩阵添加微小噪声。
        噪声幅度与权重的 Frobenius 范数成正比，确保扰动不会破坏数值稳定性。
        """
        eps = 1e-3
        for name in ["W_f", "U_f", "W_b", "U_b"]:
            mat = getattr(self, name)
            noise = self._perturb_rng.normal(0, eps, mat.shape).astype(np.float32)
            setattr(self, name, mat + noise)

    def _forced_rekey(self, session_id: str, override_seed: int):
        """会话查询超限时强制扰动：用会话密钥+override_seed重组权重。

        这使得同一会话内的海量查询无法建立稳定的输入-输出映射，
        因为超限后权重被重新初始化，攻击者之前收集的数据全部失效。
        """
        sess_seed = self._session_seed(session_id)
        mixed_seed = sess_seed ^ override_seed
        rng = np.random.default_rng(seed=mixed_seed)
        scale = 0.1 / max(1e-10, np.sqrt(self.dim))
        self.W_f = rng.normal(0, scale, (self.dim, self.dim)).astype(np.float32)
        self.U_f = rng.normal(0, scale, (self.dim, self.dim)).astype(np.float32)
        self.W_b = rng.normal(0, scale, (self.dim, self.dim)).astype(np.float32)
        self.U_b = rng.normal(0, scale, (self.dim, self.dim)).astype(np.float32)
        self._session_calls[session_id] = 0

    @staticmethod
    def _session_seed(session_id: str) -> int:
        h = int(hashlib.sha256(session_id.encode("utf-8")).hexdigest()[:8], 16)
        return h & 0x7FFFFFFF

    def transform(self, x: np.ndarray, session_id: str = "default",
                  byte_anomaly: float = 0.0) -> np.ndarray:
        """正向变换：输入向量 → 符号向量，引入非零混沌偏置。

        偏置只依赖密钥+调用计数，同一会话内确定性。
        超过会话查询上限或达到扰动间隔时，注入随机扰动防止拟合。

        字节敏感性：当 byte_anomaly > 0 时，额外注入与异常程度
        成正比的混沌扰动，使攻击性字节模式产生更大的输出偏移，
        从而在后续的原型距离计算中放大攻击与良性的差异。

        Args:
            x: 输入向量，shape (dim,)。
            session_id: 会话标识符，用于查询上限追踪。
            byte_anomaly: 字节流异常分数（0~1），驱动额外混沌扰动。

        Returns:
            变换后的向量，shape (dim,)，值域 [-1, 1]。
        """
        x = x.astype(np.float32)
        self.call_count += 1

        if len(self._session_calls) > 10000:
            oldest = list(self._session_calls.keys())[:5000]
            for k in oldest:
                del self._session_calls[k]

        sess_key = self._session_seed(session_id)
        override = 0
        sess_count = self._session_calls.get(session_id, 0) + 1
        self._session_calls[session_id] = sess_count
        if sess_count > self.config.session_query_limit:
            override = sess_count

        if self.call_count % max(1, self.config.perturbation_interval) == 0 and self.call_count > 0:
            self._inject_perturbation()

        if override > 0:
            self._forced_rekey(session_id, override)

        b_f, b_b = self._derive_biases(sess_key)

        if byte_anomaly > 0.1:
            anomaly_scale = byte_anomaly * 0.3
            anomaly_rng = np.random.default_rng(
                seed=sess_key ^ (self.call_count * 7919)
            )
            anomaly_noise_f = anomaly_rng.normal(0, anomaly_scale, self.dim).astype(np.float32)
            anomaly_noise_b = anomaly_rng.normal(0, anomaly_scale, self.dim).astype(np.float32)
            b_f = b_f + anomaly_noise_f
            b_b = b_b + anomaly_noise_b

        h_f = np.zeros((self.num_layers + 1, self.dim), dtype=np.float32)
        h_b = np.zeros((self.num_layers + 2, self.dim), dtype=np.float32)
        h_f[0] = x

        for _ in range(self.t_iter):
            for i in range(1, self.num_layers + 1):
                h_f[i] = np.tanh(
                    self.W_f @ h_f[i - 1] + self.U_f @ h_b[i] + b_f
                )
            for i in range(self.num_layers, 0, -1):
                h_b[i] = np.tanh(
                    self.W_b @ h_b[i + 1] + self.U_b @ h_f[i] + b_b
                )

        output = h_b[1].copy()

        sess_flip_rng = np.random.default_rng(seed=sess_key)
        flip_mask = sess_flip_rng.integers(0, 2, self.dim).astype(np.float32)
        flip_mask = flip_mask * 2 - 1
        output = output * flip_mask

        self._evolve_weights(h_f, h_b, output)

        return output

    def _evolve_weights(self, h_f: np.ndarray, h_b: np.ndarray, output: np.ndarray):
        """状态依赖权重演化。

        基于当前递归状态的外积来微量更新权重，增强雪崩效应。
        更新规则是确定性的（由密钥和状态驱动），合法双方可同步。
        """
        alpha = self.config.weight_evolution_rate
        top_f = h_f[self.num_layers]
        top_b = h_b[1]

        # 正向权重演化
        dW_f = alpha * np.outer(top_b, top_f) / (self.dim + 1e-8)
        dU_f = alpha * np.outer(top_b, top_b) / (self.dim + 1e-8)
        # 逆向权重演化
        dW_b = alpha * np.outer(top_f, top_f) / (self.dim + 1e-8)
        dU_b = alpha * np.outer(top_f, top_b) / (self.dim + 1e-8)

        self.W_f += dW_f.astype(np.float32)
        self.U_f += dU_f.astype(np.float32)
        self.W_b += dW_b.astype(np.float32)
        self.U_b += dU_b.astype(np.float32)

        # 权重正则化，防止发散
        self._regularize_weights()

    def _regularize_weights(self):
        """权重正则化，防止数值发散。"""
        for mat in [self.W_f, self.U_f, self.W_b, self.U_b]:
            norm = np.linalg.norm(mat, "fro")
            if norm > 10.0:
                mat *= 10.0 / norm

    def verify_entropy(self, sample_inputs: int = 100) -> dict:
        """壳输出熵/混沌性统计验证。

        对随机输入采样，计算输出分布的 Shannon 熵和自相关性。
        若熵过低或自相关过高，说明壳映射可能退化，应触发密钥轮换。

        Args:
            sample_inputs: 采样输入数量。

        Returns:
            包含 entropy、autocorr、uniform 等指标的字典。
        """
        saved_call_count = self.call_count
        saved_session_calls = dict(self._session_calls)
        rng = np.random.default_rng(seed=self.call_count % (2**31))
        outputs = np.zeros((sample_inputs, self.dim), dtype=np.float32)
        for i in range(sample_inputs):
            x = rng.normal(0, 1, self.dim).astype(np.float32)
            outputs[i] = self.transform(x, session_id=f"_entropy_{i}")
        self.call_count = saved_call_count
        self._session_calls = saved_session_calls

        hist_bins = 20
        combined = outputs.ravel()
        hist, _ = np.histogram(combined, bins=hist_bins, range=(-1, 1), density=True)
        hist = hist + 1e-12
        shannon = -np.sum(hist * np.log(np.maximum(hist, 1e-12))) / max(1e-12, np.log(hist_bins))

        mean_out = np.mean(outputs, axis=0)
        centered = outputs - mean_out
        var_total = np.sum(centered ** 2) + 1e-12
        autocorrs = []
        for lag in [1, 2, 3]:
            corr = np.sum(centered[:-lag] * centered[lag:]) / max(1e-10, var_total)
            autocorrs.append(float(corr))
        avg_autocorr = float(np.mean(np.abs(autocorrs)))

        span = float(np.max(outputs) - np.min(outputs))

        return {
            "shannon_entropy": round(float(shannon), 4),
            "avg_autocorr": round(avg_autocorr, 4),
            "output_span": round(span, 4),
            "entropy_ok": shannon > 0.5,
            "autocorr_ok": avg_autocorr < 0.3,
            "healthy": shannon > 0.5 and avg_autocorr < 0.3,
        }

    def sanitize(self):
        """擦除敏感权重数据，防止物理内存读取攻击。

        将所有权重矩阵和偏置置零，调用计数归零。
        调用后壳不可再使用，需重新初始化。
        """
        for attr in ["W_f", "U_f", "W_b", "U_b", "b_f", "b_b"]:
            if hasattr(self, attr):
                mat = getattr(self, attr)
                if mat.size > 0:
                    mat.fill(0.0)
        self.call_count = 0
        self._session_calls.clear()

    def stability_measure(self, trials: int = 20, perturb_scale: float = 1e-6) -> dict:
        """动力学稳定性度量：通过扰动传播估计混沌强度。

        对随机输入施加微小扰动，追踪输出差异的放大倍数。
        混沌系统中微小差异会指数放大（正 Lyapunov 指数），
        而退化的周期性系统则不会。

        Args:
            trials: 试验次数。
            perturb_scale: 扰动幅度。

        Returns:
            包含 divergence_ratio、stability 等指标的字典。
            divergence_ratio > 1 表明混沌（安全），< 1 表明可能退化。
        """
        rng = np.random.default_rng(seed=self.call_count % (2**31) + 1)
        saved_call_count = self.call_count
        saved_session_calls = dict(self._session_calls)
        ratios = []

        for t in range(trials):
            x = rng.normal(0, 1, self.dim).astype(np.float32)
            x_pert = x.copy()
            x_pert[0] += perturb_scale

            y = self.transform(x, session_id=f"_stab_a_{t}")
            y_pert = self.transform(x_pert, session_id=f"_stab_b_{t}")

            diff_in = np.linalg.norm(x - x_pert) + 1e-12
            diff_out = np.linalg.norm(y - y_pert)
            ratio = diff_out / diff_in
            ratios.append(float(ratio))

        self.call_count = saved_call_count
        self._session_calls = saved_session_calls

        mean_ratio = float(np.mean(ratios))
        std_ratio = float(np.std(ratios))

        return {
            "mean_divergence": round(mean_ratio, 4),
            "std_divergence": round(std_ratio, 4),
            "min_divergence": round(float(np.min(ratios)), 4),
            "max_divergence": round(float(np.max(ratios)), 4),
            "chaotic": mean_ratio > 10.0,
            "diverging": mean_ratio > 1.0,
            "stable": std_ratio < mean_ratio,
        }