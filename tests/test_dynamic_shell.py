# 动态阴阳壳 单元测试 — 状态依赖权重演化

import numpy as np
import pytest

from daoti_xuandun.config import XuanDunConfig
from daoti_xuandun.dynamic_shell import DynamicShell


class TestDynamicShell:
    """动态阴阳壳单元测试。"""

    def test_shell_deterministic_same_call_count(self):
        """相同调用计数下，相同输入产生相同输出。"""
        config = XuanDunConfig(hidden_dim=16, num_layers=2, t_iter=3, shell_key=b"fixed_key_16b")
        shell1 = DynamicShell(config)
        shell2 = DynamicShell(config)
        x = np.random.randn(16).astype(np.float32)
        y1 = shell1.transform(x)
        y2 = shell2.transform(x)
        assert np.allclose(y1, y2)

    def test_shell_different_call_counts(self):
        """相同输入不同调用计数，输出应不同（偏置演化）。"""
        config = XuanDunConfig(hidden_dim=16, shell_key=b"test_key_16b!!!")
        shell = DynamicShell(config)
        x = np.random.randn(16).astype(np.float32)
        y1 = shell.transform(x)
        y2 = shell.transform(x)
        assert not np.allclose(y1, y2)

    def test_shell_sensitivity(self):
        """不同密钥产生不同输出。"""
        config1 = XuanDunConfig(hidden_dim=16, shell_key=b"key1_key1_key1!")
        config2 = XuanDunConfig(hidden_dim=16, shell_key=b"key2_key2_key2!")
        shell1 = DynamicShell(config1)
        shell2 = DynamicShell(config2)
        x = np.random.randn(16).astype(np.float32)
        y1 = shell1.transform(x)
        y2 = shell2.transform(x)
        assert not np.allclose(y1, y2)

    def test_zero_vector_not_zero_output(self):
        """零向量输入应产生非零输出（非零偏置）。"""
        config = XuanDunConfig(hidden_dim=32, chaos_phase_scale=0.2)
        shell = DynamicShell(config)
        x = np.zeros(32, dtype=np.float32)
        y = shell.transform(x)
        assert not np.allclose(y, 0)

    def test_output_shape(self):
        """输出形状与输入一致。"""
        config = XuanDunConfig(hidden_dim=32)
        shell = DynamicShell(config)
        x = np.random.randn(32).astype(np.float32)
        y = shell.transform(x)
        assert y.shape == (32,)
        assert y.dtype == np.float32

    def test_output_range(self):
        """tanh 输出在 [-1, 1] 范围内。"""
        config = XuanDunConfig(hidden_dim=16, chaos_phase_scale=0.1)
        shell = DynamicShell(config)
        x = np.random.randn(16).astype(np.float32) * 100
        y = shell.transform(x)
        assert np.all(y >= -1.0)
        assert np.all(y <= 1.0)

    def test_output_finite(self):
        """输出应为有限值。"""
        config = XuanDunConfig(hidden_dim=32, num_layers=5, t_iter=10)
        shell = DynamicShell(config)
        x = np.random.randn(32).astype(np.float32)
        y = shell.transform(x)
        assert np.all(np.isfinite(y))

    def test_weight_evolution_happens(self):
        """权重演化确实发生了。"""
        config = XuanDunConfig(hidden_dim=16, weight_evolution_rate=0.01)
        shell = DynamicShell(config)
        W_f_before = shell.W_f.copy()
        shell.transform(np.random.randn(16).astype(np.float32))
        assert not np.allclose(shell.W_f, W_f_before)

    def test_weight_regularization(self):
        """权重正则化防止发散。"""
        config = XuanDunConfig(hidden_dim=16, weight_evolution_rate=0.1)
        shell = DynamicShell(config)
        for _ in range(100):
            shell.transform(np.random.randn(16).astype(np.float32))
        for mat in [shell.W_f, shell.U_f, shell.W_b, shell.U_b]:
            assert np.linalg.norm(mat, "fro") <= 15.0

    def test_extreme_inputs(self):
        """极端输入不崩溃。"""
        config = XuanDunConfig(hidden_dim=16)
        shell = DynamicShell(config)
        shell.transform(np.full(16, np.nan, dtype=np.float32))
        shell.transform(np.full(16, np.inf, dtype=np.float32))
        shell.transform(np.full(16, 1e30, dtype=np.float32))
        shell.transform(np.zeros(16, dtype=np.float32))

    def test_chaotic_series(self):
        """混沌序列生成器正常工作。"""
        from daoti_xuandun.dynamic_shell import _chaotic_series

        s = _chaotic_series(42, 100)
        assert len(s) == 100
        assert np.all((s >= 0) & (s <= 1))