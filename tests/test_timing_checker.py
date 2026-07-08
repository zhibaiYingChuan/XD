# Implements §6.4 单元测试

import numpy as np
import pytest

from daoti_xuandun.config import XuanDunConfig
from daoti_xuandun.timing_checker import TimingConsistencyChecker
from daoti_xuandun.types import TimingDecision


class TestTimingConsistencyChecker:
    """§6.4 时序一致性校验单元测试。"""

    @pytest.fixture
    def config(self):
        return XuanDunConfig(
            hidden_dim=6,
            symbol_table_size=64,
            max_window_size=5,
            anomaly_threshold=2.0,
        )

    def test_timing_check_accept_repetitive(self, config):
        """§6.4: 重复模式持续放行。"""
        checker = TimingConsistencyChecker(config)
        session = "test"
        sym_seq = [0, 1, 2, 0, 1, 2]
        for _ in range(10):
            decision, dist = checker.check(sym_seq, session)
            assert decision == TimingDecision.PASS

    def test_timing_check_reject_anomaly(self, config):
        """§6.4: 异常序列触发告警。"""
        checker = TimingConsistencyChecker(config)
        session = "test"
        normal_seq = [0] * 6
        for _ in range(config.max_window_size):
            checker.check(normal_seq, session)
        abnormal_seq = [63] * 6
        decision, dist = checker.check(abnormal_seq, session)
        assert decision in (TimingDecision.WARN, TimingDecision.REJECT)
        assert dist > 0

    def test_timing_check_window_not_full(self, config):
        """窗口未满时应直接放行。"""
        checker = TimingConsistencyChecker(config)
        session = "new_session"
        sym_seq = [10, 20, 30, 10, 20, 30]
        for _ in range(config.max_window_size - 1):
            decision, dist = checker.check(sym_seq, session)
            assert decision == TimingDecision.PASS
            assert dist == 0.0

    def test_timing_check_session_isolation(self, config):
        """不同会话状态应隔离。"""
        checker = TimingConsistencyChecker(config)
        checker.check([0] * 6, "session_a")
        checker.check([0] * 6, "session_b")
        assert "session_a" in checker.state
        assert "session_b" in checker.state
        assert len(checker.state["session_a"]) == 1
        assert len(checker.state["session_b"]) == 1

    def test_extract_feature(self, config):
        """特征提取测试。"""
        checker = TimingConsistencyChecker(config)
        sym_seq = [0, 0, 1, 1, 2, 2]
        feat = checker._extract_feature(sym_seq)
        assert feat.shape == (64,)
        assert np.isclose(np.sum(feat), 1.0)
        assert feat[0] > 0
        assert feat[1] > 0
        assert feat[2] > 0

    def test_mahalanobis_identical(self):
        """相同向量马氏距离应为 0。"""
        x = np.array([0.5, 0.3, 0.2], dtype=np.float64)
        mean = x.copy()
        cov = np.eye(3) * 0.1
        cov_inv = np.linalg.inv(cov)
        dist = TimingConsistencyChecker._mahalanobis(x, mean, cov_inv)
        assert np.isclose(dist, 0.0)

    def test_mahalanobis_positive(self):
        """不同向量马氏距离应 > 0。"""
        x = np.array([0.5, 0.3, 0.2], dtype=np.float64)
        mean = np.array([0.0, 0.0, 0.0], dtype=np.float64)
        cov = np.eye(3) * 0.1
        cov_inv = np.linalg.inv(cov)
        dist = TimingConsistencyChecker._mahalanobis(x, mean, cov_inv)
        assert dist > 0
