# 集成测试 — 道体动态活性架构

import numpy as np
import pytest

from daoti_xuandun import XuanDunConfig, XuanDun, ProtectResult, TrustLevel


class TestXuanDunIntegration:
    """XuanDun 集成测试。"""

    def test_full_pipeline_with_seed(self):
        """播种后全流程通过。"""
        config = XuanDunConfig(
            hidden_dim=16,
            num_layers=2,
            t_iter=2,
            symbol_table_size=16,
            max_window_size=5,
            anomaly_threshold=5.0,
            chaos_nursery_size=4,
            prototype_distance_threshold=0.5,
        )
        xuandun = XuanDun(config)
        xuandun.seed(["论语有云学而时习之", "黄帝内经曰上古之人"])
        result = xuandun.protect("论语学而时习之不亦说乎", session_id="test")
        assert result.allowed is True
        assert result.final_output is not None
        assert len(result.final_output) == 16

    def test_reject_unknown_domain(self):
        """未知域输入：软拒绝机制允许低异常输入以低信任度通过。"""
        config = XuanDunConfig(
            hidden_dim=32,
            enable_dynamic_shell=False,
            enable_ancient_map=False,
            enable_timing_check=False,
            prototype_distance_threshold=0.4,
            chaos_nursery_size=4,
        )
        xuandun = XuanDun(config)
        xuandun.seed(["论语有云学而时习之"])
        seed_vec = xuandun.domain_awareness._input_to_vector("论语有云学而时习之")
        far_vec = -seed_vec + np.random.randn(32).astype(np.float32) * 0.1
        result = xuandun.protect(far_vec)
        assert result.allowed is True
        assert result.trust_level == TrustLevel.LOW

    def test_trust_level_in_result(self):
        """ProtectResult 包含信任等级和域距离。"""
        config = XuanDunConfig(
            hidden_dim=16,
            symbol_table_size=16,
            prototype_distance_threshold=0.5,
            chaos_nursery_size=4,
        )
        xuandun = XuanDun(config)
        xuandun.seed(["论语有云学而时习之"])
        result = xuandun.protect("论语学而时习之", session_id="test")
        assert result.trust_level in (TrustLevel.HIGH, TrustLevel.MEDIUM)
        assert result.domain_distance is not None

    def test_zero_vector_different_behavior(self):
        """零向量输入的行为验证（非零偏置确保符号映射正常）。"""
        config = XuanDunConfig(
            hidden_dim=16,
            chaos_phase_scale=0.2,
            prototype_distance_threshold=0.99,
            chaos_nursery_size=4,
        )
        xuandun = XuanDun(config)
        xuandun.seed(["论语学而时习之"])
        zero_vec = np.zeros(16, dtype=np.float32)
        result = xuandun.protect(zero_vec, session_id="zero_test")
        # 零向量在宽阈值下应通过，但信任级别可能为 LOW
        assert result.trust_level is not None

    def test_module_toggle(self):
        """模块开关组合。"""
        configs = {
            "全模块": XuanDunConfig(hidden_dim=16, chaos_nursery_size=4),
            "无门禁": XuanDunConfig(hidden_dim=16, enable_reject_gate=False, chaos_nursery_size=4),
            "无阴阳壳": XuanDunConfig(
                hidden_dim=16, enable_dynamic_shell=False, chaos_nursery_size=4
            ),
            "全禁用": XuanDunConfig(
                hidden_dim=16,
                enable_reject_gate=False,
                enable_dynamic_shell=False,
                enable_ancient_map=False,
                enable_timing_check=False,
            ),
        }
        for name, cfg in configs.items():
            xuandun = XuanDun(cfg)
            if cfg.enable_reject_gate:
                xuandun.seed(["论语有云基础安全文本"])
            result = xuandun.protect("论语基础安全文本", session_id="toggle")
            assert isinstance(result, ProtectResult)

    def test_pipeline_without_domain_awareness(self):
        """禁用域感知时其余模块正常。"""
        config = XuanDunConfig(
            hidden_dim=16,
            enable_reject_gate=False,
            symbol_table_size=16,
            max_window_size=5,
            anomaly_threshold=5.0,
        )
        xuandun = XuanDun(config)
        result = xuandun.protect("正常输入文本测试", session_id="no_domain")
        assert result.allowed is True
        assert result.final_output is not None

    def test_timing_reject(self):
        """时序校验拒绝异常。"""
        config = XuanDunConfig(
            hidden_dim=16,
            chaos_nursery_size=4,
            symbol_table_size=16,
            max_window_size=3,
            anomaly_threshold=0.1,
            enable_dynamic_shell=False,
        )
        xuandun = XuanDun(config)
        xuandun.seed(["normal phrase one", "normal phrase two"])
        for _ in range(config.max_window_size):
            xuandun.protect("normal input here", session_id="timing")
        result = xuandun.protect("completely different abnormal exploit hack", session_id="timing")
        assert result.allowed is False
        assert result.reject_stage == "timing_checker"

    def test_seed_method(self):
        """播种方法正常工作。auto_warmup 会额外播种预热样本。"""
        config = XuanDunConfig(hidden_dim=16)
        xuandun = XuanDun(config)
        xuandun.seed(["安全文本1", "安全文本2", "安全文本3"])
        assert xuandun.domain_awareness.num_prototypes >= 3

    def test_no_seed_cold_start(self):
        """auto_warmup 预热后，软拒绝机制允许输入通过。"""
        config = XuanDunConfig(hidden_dim=16, chaos_nursery_size=4)
        xuandun = XuanDun(config)
        result = xuandun.protect("first ever input")
        assert result.allowed is True