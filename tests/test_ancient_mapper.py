# 自组织符号映射 单元测试

import numpy as np
import pytest

from daoti_xuandun.config import XuanDunConfig
from daoti_xuandun.ancient_mapper import SelfOrganizingMapper


class TestSelfOrganizingMapper:
    """自组织符号映射单元测试。"""

    @pytest.fixture
    def config(self):
        return XuanDunConfig(hidden_dim=32, symbol_table_size=16)

    @pytest.fixture
    def mapper(self, config):
        return SelfOrganizingMapper(config)

    def test_map_output_length(self, mapper):
        """输出长度等于输入维度。"""
        vec = np.random.randn(32).astype(np.float32)
        seq = mapper.map(vec)
        assert len(seq) == 32

    def test_map_output_range(self, mapper):
        """符号值在合法范围内。"""
        vec = np.random.randn(32).astype(np.float32) * 100
        seq = mapper.map(vec)
        assert all(0 <= s < 16 for s in seq)

    def test_prototype_adjustment(self, mapper):
        """原型在线调整后发生变化。"""
        before = mapper.prototypes[0].copy()
        vec = np.ones(32, dtype=np.float32) * 10
        mapper.map(vec)
        assert not np.allclose(mapper.prototypes[0], before)

    def test_inverse_map(self, mapper):
        """逆映射维度正确。"""
        symbols = [0, 1, 2, 3, 4]
        recovered = mapper.inverse_map(symbols)
        assert recovered.shape == (5, 32)

    def test_expand_table(self, mapper):
        """符号表扩展。"""
        assert mapper.current_table_size == 16
        mapper.expand_table(32)
        assert mapper.current_table_size == 32
        assert mapper.prototypes.shape == (32, 32)

    def test_expand_table_no_shrink(self, mapper):
        """不能缩表。"""
        mapper.expand_table(8)
        assert mapper.current_table_size == 16

    def test_prototypes_normalized(self, mapper):
        """原型向量应归一化。"""
        for i in range(mapper.table_size):
            norm = np.linalg.norm(mapper.prototypes[i])
            assert np.isclose(norm, 1.0, atol=1e-4)

    def test_map_different_inputs_different_outputs(self, mapper):
        """不同输入应倾向产生不同符号序列。"""
        vec1 = np.ones(32, dtype=np.float32)
        vec2 = -np.ones(32, dtype=np.float32)
        seq1 = mapper.map(vec1)
        seq2 = mapper.map(vec2)
        diff_count = sum(1 for a, b in zip(seq1, seq2) if a != b)
        assert diff_count > 0

    def test_extreme_inputs(self, mapper):
        """极端输入不崩溃。"""
        mapper.map(np.zeros(32, dtype=np.float32))
        mapper.map(np.full(32, 1e10, dtype=np.float32))
        mapper.map(np.full(32, -1e10, dtype=np.float32))
        mapper.map(np.full(32, np.nan, dtype=np.float32))
        mapper.map(np.full(32, np.inf, dtype=np.float32))

    def test_prototype_no_degenerate(self, mapper):
        """多轮迭代后原型不退化。"""
        for _ in range(500):
            mapper.map(np.random.randn(32).astype(np.float32))
        for i in range(mapper.table_size):
            norm = np.linalg.norm(mapper.prototypes[i])
            assert np.isclose(norm, 1.0, atol=2e-3)

    def test_step_counter(self, mapper):
        """步数计数器正常递增。"""
        assert mapper.step_count == 0
        mapper.map(np.random.randn(32).astype(np.float32))
        assert mapper.step_count == 1

    def test_different_keys_different_mappings(self):
        """不同密钥产生不同映射。"""
        config1 = XuanDunConfig(hidden_dim=32, symbol_table_size=16, mapping_key=b"key_a_key_a_key!")
        config2 = XuanDunConfig(hidden_dim=32, symbol_table_size=16, mapping_key=b"key_b_key_b_key!")
        m1 = SelfOrganizingMapper(config1)
        m2 = SelfOrganizingMapper(config2)
        vec = np.random.randn(32).astype(np.float32)
        seq1 = m1.map(vec)
        seq2 = m2.map(vec)
        assert seq1 != seq2