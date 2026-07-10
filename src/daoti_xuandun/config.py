# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白
# 本文件受道体研究许可证 v1.0 约束，禁止逆向工程和再分发
# 详见 LICENSE 文件

# Implements §2.1 配置对象 XuanDunConfig — 道体动态活性架构

from dataclasses import dataclass
from enum import Enum
from typing import Optional
import os

from .secure_strings import secure_value


class DefenseLevel(Enum):
    """防御层级预设，平衡安全性与性能开销。

    BASIC:    最小防御，适合低延迟内部服务
    STANDARD: 均衡防御，适合通用 API 网关（默认）
    STRICT:   增强防御，适合面向公网的高价值服务
    PARANOID: 极限防御，适合金融/国防等高威胁场景
    """
    BASIC = "BASIC"
    STANDARD = "STANDARD"
    STRICT = "STRICT"
    PARANOID = "PARANOID"

    @property
    def description(self) -> str:
        return _LEVEL_DESCRIPTIONS.get(self, "")

    @property
    def perf_overhead_pct(self) -> float:
        return _LEVEL_OVERHEAD.get(self, 0.0)


_LEVEL_DESCRIPTIONS = {
    DefenseLevel.BASIC: "最小防御，无熵校验/延迟/投影，适合低延迟内部服务",
    DefenseLevel.STANDARD: "均衡防御，开启核心防护，适合通用 API 网关",
    DefenseLevel.STRICT: "增强防御，开启侧信道+边界模糊，适合公网高价值服务",
    DefenseLevel.PARANOID: "极限防御，全开+熵校验+完整性校验，适合金融/国防场景",
}

_LEVEL_OVERHEAD = {
    DefenseLevel.BASIC: 0.0,
    DefenseLevel.STANDARD: 5.0,
    DefenseLevel.STRICT: 12.0,
    DefenseLevel.PARANOID: 25.0,
}


@dataclass
class XuanDunConfig:
    """道体·玄盾全局配置对象。

    所有随机性由配置中的 key 种子驱动，确保可重现。
    动态自适应机制无需预训练，开箱即用，在线演化。
    """

    # 内生域感知（取代静态域分类器）
    enable_reject_gate: bool = True
    prototype_max_size: int = 512          # 原型记忆库最大容量
    prototype_distance_threshold: float = float(secure_value("prototype_distance_threshold_default", "0.65"))  # 未知域判定距离阈值
    chaos_nursery_size: int = 8            # 新生儿混沌期候选队列长度
    prototype_learning_rate: float = 0.01  # 原型在线学习率
    ewma_alpha: float = 0.1                # EWMA 平滑系数，抗污染
    threshold_floor: float = 0.15          # 阈值硬下限，防止被拉低
    reject_boundary_multiplier: float = float(secure_value("reject_boundary_multiplier_default", "3.0"))  # 拒绝边界乘数，基于 base 阈值
    structural_anomaly_threshold: float = float(secure_value("structural_anomaly_threshold_default", "0.35"))  # 结构异常分数阈值，超过此值的域外输入被拒绝

    # 动态阴阳壳
    enable_dynamic_shell: bool = True
    hidden_dim: int = 128
    num_layers: int = 3
    t_iter: int = 5
    shell_key: Optional[bytes] = None
    weight_evolution_rate: float = 0.005   # 权重动态演化率
    chaos_phase_scale: float = 0.6
    session_query_limit: int = 100000      # 会话最大查询数，超限后强制扰动
    perturbation_interval: int = 1000      # 每 N 次调用注入随机扰动

    # 自组织符号映射
    enable_ancient_map: bool = True
    symbol_table_size: int = 64
    mapping_key: Optional[bytes] = None
    som_learning_rate: float = 0.05        # SOM 原型学习率
    som_initial_expand: bool = True        # 是否动态扩展符号表
    som_history_cache_size: int = 2048     # 输入→符号的历史缓存，保证一致性

    # 洛书符号映射器（语言无关的纯符号级安全域表征）
    enable_luoshu_mapper: bool = True      # 启用洛书映射器，替代语言特征依赖
    luoshu_safe_distance_weight: float = 0.3  # 洛书安全距离信号权重
    luoshu_attack_distance_weight: float = 0.4  # 洛书攻击距离信号权重
    luoshu_density_weight: float = 0.2     # 洛书局部密度信号权重
    language_feature_decay_safe_threshold: int = 100   # 安全原型数>此值时开始衰减语言特征
    language_feature_decay_attack_threshold: int = 50  # 攻击原型数>此值时开始衰减语言特征
    language_feature_decay_mid_weight: float = 0.5     # 阶段二语言特征权重
    language_feature_decay_full_safe: int = 500        # 安全原型数>此值时完全移除语言特征
    language_feature_decay_full_attack: int = 200      # 攻击原型数>此值时完全移除语言特征
    luoshu_confidence_exempt_safe: float = 0.2         # 洛书安全距离<此值时豁免语言特征（强安全信号）
    luoshu_confidence_exempt_attack: float = 0.15      # 洛书攻击距离<此值时豁免语言特征（强攻击信号）
    luoshu_confidence_borderline_safe: float = 0.4     # 安全距离在此区间时降低语言特征权重
    luoshu_confidence_borderline_attack: float = 0.35  # 攻击距离在此区间时降低语言特征权重
    luoshu_confidence_borderline_weight: float = 0.5   # 边界区域语言特征权重

    # 时序一致性校验
    enable_timing_check: bool = True
    max_window_size: int = 32
    anomaly_threshold: float = 2.0
    state_ttl: int = 3600
    timing_ewma_alpha: float = 0.1       # 时序 EWMA 平滑系数
    timing_threshold_floor: float = 0.5   # 时序阈值硬下限

    # 会话管理
    max_sessions: int = 10000             # 最大会话数，超限 LRU 淘汰
    session_ttl: int = 7200               # 会话过期时间（秒）

    # 侧信道防御
    side_channel_delay: bool = False       # 是否启用随机延迟掩码（抗时序分析）
    side_channel_delay_us: int = 500      # 随机延迟范围（微秒），实际延迟在 [0, max] 均匀分布

    # 边界枚举防御
    prototype_distance_noise: float = 0.0  # 原型距离噪声标准差，模糊边界防枚举
    prototype_projection_scale: float = 0.0  # 高维随机投影扰动强度，0=关闭，推荐 0.01~0.05

    # 全局速率限制
    global_qps_limit: int = 0              # 全局 QPS 上限，0 表示不限

    # 活性防护增强（抗理论级攻击）
    enable_entropy_guard: bool = False     # 壳输出熵/混沌性统计验证，检测退化
    entropy_check_interval: int = 10000    # 每 N 次调用执行一次熵校验
    entropy_min_threshold: float = 0.7     # 最小熵阈值（归一化），低于此值触发告警
    enable_memory_sanitize: bool = True    # 是否在关键操作后擦除敏感数据
    enable_integrity_check: bool = False   # 密钥完整性校验，检测篡改

    # BASIC层级安全确认
    require_acknowledgement: bool = False  # BASIC层级是否要求用户显式确认安全风险

    # EWMA预热安全锁
    lock_negation_weights_after_warmup: bool = False  # 预热完成后锁定否定信号权重，防止运行时污染

    # 观察→学习→自动切换（活性防护架构）
    enable_observing_mode: bool = True      # 启用观察模式：接入后先旁听学习，积累样本后自动切换到拦截
    min_samples_for_switch: int = 1000      # 自动切换到保护模式所需的最小正常样本数
    enable_builtin_attacks: bool = True     # 启用内置攻击样本（让洛书攻击原型库从一开始就不为空）

    # 预处理管道（可选，不影响核心架构）
    enable_decode_preprocess: bool = True   # 启用 Base64/Hex 解码预处理，检测编码攻击
    enable_unicode_normalize: bool = True   # 启用 Unicode 正规化，降低混淆良性误拒
    enable_imperative_whitelist: bool = True  # 启用命令式短语白名单，降低技术性良性误拒

    # 调试模式
    debug: bool = False  # 启用调试模式，输出决策路径信息（不暴露算法细节）
    verbose_debug: bool = False  # 详细调试模式（仅用于离线诊断，输出信号强度归一化值）

    def __post_init__(self):
        if self.shell_key is None:
            env_key = os.environ.get("XUANDUN_SHELL_KEY")
            if env_key:
                self.shell_key = env_key.encode("utf-8")
            else:
                import sys
                sys.stderr.write("[XuanDun] WARNING: XUANDUN_SHELL_KEY not set, using insecure fallback key\n")
                self.shell_key = b"daoti_xuandun_16"
        if self.mapping_key is None:
            env_key = os.environ.get("XUANDUN_MAPPING_KEY")
            if env_key:
                self.mapping_key = env_key.encode("utf-8")
            else:
                import sys
                sys.stderr.write("[XuanDun] WARNING: XUANDUN_MAPPING_KEY not set, using insecure fallback key\n")
                self.mapping_key = b"ancient_map_16b!"

    @classmethod
    def for_level(cls, level: DefenseLevel, **overrides) -> "XuanDunConfig":
        """按防御层级生成预配置实例（preset的别名）。

        Args:
            level: 防御层级。
            **overrides: 可选覆写参数。

        Returns:
            对应层级的 XuanDunConfig 实例。
        """
        return cls.preset(level, **overrides)

    @classmethod
    def preset(cls, level: DefenseLevel, **overrides) -> "XuanDunConfig":
        """按防御层级生成预配置实例。

        Args:
            level: 防御层级。
            **overrides: 可选覆写参数。

        Returns:
            对应层级的 XuanDunConfig 实例。
        """
        if level == DefenseLevel.BASIC:
            cfg = cls(
                hidden_dim=64, num_layers=2, t_iter=3,
                prototype_max_size=256, symbol_table_size=32,
                prototype_distance_threshold=float(secure_value("prototype_distance_threshold_basic", "0.50")),
                threshold_floor=0.15,
                reject_boundary_multiplier=float(secure_value("reject_boundary_multiplier_basic", "2.0")),
                structural_anomaly_threshold=float(secure_value("structural_anomaly_threshold_basic", "0.40")),
                max_window_size=16, max_sessions=5000,
                side_channel_delay=False, prototype_distance_noise=0.0,
                prototype_projection_scale=0.0, global_qps_limit=0,
                enable_entropy_guard=False, enable_integrity_check=False,
                perturbation_interval=5000, session_query_limit=100000,
                enable_imperative_whitelist=True,
            )
        elif level == DefenseLevel.STRICT:
            cfg = cls(
                hidden_dim=128, num_layers=4, t_iter=7,
                prototype_max_size=512, symbol_table_size=64,
                prototype_distance_threshold=float(secure_value("prototype_distance_threshold_strict", "0.45")),
                threshold_floor=0.18,
                reject_boundary_multiplier=float(secure_value("reject_boundary_multiplier_strict", "2.2")),
                structural_anomaly_threshold=float(secure_value("structural_anomaly_threshold_strict", "0.30")),
                max_window_size=32, max_sessions=10000,
                side_channel_delay=True, side_channel_delay_us=300,
                prototype_distance_noise=0.01, prototype_projection_scale=0.02,
                global_qps_limit=5000, enable_entropy_guard=True,
                entropy_check_interval=5000, enable_integrity_check=True,
                perturbation_interval=500, session_query_limit=50000,
                enable_decode_preprocess=True, enable_unicode_normalize=True,
            )
        elif level == DefenseLevel.PARANOID:
            cfg = cls(
                hidden_dim=256, num_layers=5, t_iter=10,
                prototype_max_size=1024, symbol_table_size=128,
                max_window_size=64, max_sessions=5000,
                side_channel_delay=True, side_channel_delay_us=1000,
                prototype_distance_noise=0.03, prototype_projection_scale=0.05,
                global_qps_limit=1000, enable_entropy_guard=True,
                entropy_check_interval=1000, enable_integrity_check=True,
                enable_memory_sanitize=True,
                perturbation_interval=200, session_query_limit=10000,
                session_ttl=600,
            )
        else:  # STANDARD
            cfg = cls(
                hidden_dim=128, num_layers=3, t_iter=5,
                prototype_max_size=512, symbol_table_size=64,
                prototype_distance_threshold=float(secure_value("prototype_distance_threshold_standard", "0.35")),
                threshold_floor=0.15,
                reject_boundary_multiplier=float(secure_value("reject_boundary_multiplier_standard", "2.5")),
                structural_anomaly_threshold=float(secure_value("structural_anomaly_threshold_standard", "0.35")),
                max_window_size=32, max_sessions=10000,
                side_channel_delay=False, prototype_distance_noise=0.0,
                prototype_projection_scale=0.0, global_qps_limit=0,
                enable_entropy_guard=False, enable_integrity_check=False,
                perturbation_interval=1000, session_query_limit=100000,
                enable_imperative_whitelist=True,
                enable_decode_preprocess=True, enable_unicode_normalize=True,
            )

        for k, v in overrides.items():
            setattr(cfg, k, v)
        return cfg

    def performance_profile(self) -> dict:
        """返回当前配置的性能开销估算。

        Returns:
            包含各防御模块预估开销的字典。
        """
        overhead = 0.0
        modules = {}

        if self.side_channel_delay:
            oh = self.side_channel_delay_us / 10000.0
            modules["side_channel"] = round(oh, 2)
            overhead += oh

        if self.prototype_distance_noise > 0:
            oh = 0.5
            modules["distance_noise"] = oh
            overhead += oh

        if self.prototype_projection_scale > 0:
            oh = 3.0
            modules["high_dim_proj"] = oh
            overhead += oh

        if self.enable_entropy_guard:
            oh = 100.0 / max(1, self.entropy_check_interval) * 100
            modules["entropy_guard"] = round(oh, 2)
            overhead += oh

        if self.global_qps_limit > 0:
            modules["qps_limit"] = 0.5
            overhead += 0.5

        oh_dim = self.hidden_dim / 128.0 * 100 - 100
        if oh_dim > 0:
            modules["dim_overhead"] = round(oh_dim, 1)

        oh_layers = (self.num_layers - 3) * 5.0
        if oh_layers > 0:
            modules["layer_overhead"] = oh_layers

        oh_iter = (self.t_iter - 5) * 3.0
        if oh_iter > 0:
            modules["iter_overhead"] = oh_iter

        return {
            "estimated_overhead_pct": round(overhead, 1),
            "modules": modules,
            "note": "估算值基于单请求额外耗时百分比，实际值因硬件和负载而异",
        }

    @classmethod
    def tune_for_domain(cls, domain_texts: list, base_level: "DefenseLevel" = None) -> "XuanDunConfig":
        """从领域样本中自动推荐配置参数。

        活性防护哲学：不同领域有不同的文本特征分布，最佳配置应
        从数据中涌现而非凭经验猜测。本方法分析领域样本的统计特征，
        自动调整关键参数：

        - 样本平均长度 → 影响符号表大小和窗口参数
        - 词汇多样性 → 影响原型距离阈值
        - 语言分布 → 影响预热种子选择

        Args:
            domain_texts: 领域样本文本列表（建议≥10条）。
            base_level: 基础防御层级（默认STANDARD）。

        Returns:
            调优后的 XuanDunConfig 实例。
        """
        if base_level is None:
            base_level = DefenseLevel.STANDARD

        config = cls.preset(base_level)

        if not domain_texts:
            return config

        avg_len = sum(len(t) for t in domain_texts) / len(domain_texts)
        unique_chars = set()
        for t in domain_texts:
            unique_chars.update(t.lower())
        char_diversity = len(unique_chars) / max(1, sum(len(t) for t in domain_texts))

        cn_count = sum(1 for t in domain_texts for c in t if '\u4e00' <= c <= '\u9fff')
        en_count = sum(1 for t in domain_texts for c in t if 'a' <= c.lower() <= 'z')
        total_chars = sum(len(t) for t in domain_texts)
        cn_ratio = cn_count / max(1, total_chars)
        en_ratio = en_count / max(1, total_chars)

        if avg_len > 200:
            config.prototype_distance_threshold = max(0.25, config.prototype_distance_threshold - 0.05)
        elif avg_len < 30:
            config.prototype_distance_threshold = min(0.45, config.prototype_distance_threshold + 0.05)

        if char_diversity > 0.05:
            config.structural_anomaly_threshold = min(0.45, config.structural_anomaly_threshold + 0.05)
        elif char_diversity < 0.01:
            config.structural_anomaly_threshold = max(0.25, config.structural_anomaly_threshold - 0.05)

        if en_ratio > 0.7 and cn_ratio < 0.1:
            config.symbol_table_size = max(48, config.symbol_table_size)

        return config

    def recommendation(self) -> dict:
        """输出当前配置的安全/性能评估和建议。

        活性防护哲学：用户不应盲目使用配置，系统应主动告知
        当前配置的安全等级和性能预期，帮助用户做出明智决策。
        """
        profile = self.performance_profile()
        level_name = "UNKNOWN"
        if self.prototype_distance_threshold >= 0.50:
            level_name = "BASIC"
        elif self.prototype_distance_threshold >= 0.28:
            level_name = "STANDARD"
        elif self.prototype_distance_threshold >= 0.15:
            level_name = "STRICT"
        else:
            level_name = "PARANOID"

        safety_score = 0
        if self.side_channel_delay:
            safety_score += 20
        if self.enable_entropy_guard:
            safety_score += 15
        if self.prototype_distance_noise > 0:
            safety_score += 15
        if self.prototype_projection_scale > 0:
            safety_score += 10
        if self.prototype_distance_threshold < 0.30:
            safety_score += 20
        if self.structural_anomaly_threshold < 0.35:
            safety_score += 10
        if self.global_qps_limit > 0:
            safety_score += 10

        suggestions = []
        if level_name == "BASIC":
            suggestions.append("BASIC层级攻击拒绝率约48%，不建议面向公网使用")
        if not self.side_channel_delay:
            suggestions.append("未启用时序侧信道防御，建议开启side_channel_delay=True")
        if not self.enable_entropy_guard:
            suggestions.append("未启用壳输出熵校验，建议在高安全场景开启enable_entropy_guard=True")
        if self.prototype_distance_noise == 0:
            suggestions.append("未启用边界噪声，建议开启prototype_distance_noise=0.01防止边界枚举")

        return {
            "defense_level": level_name,
            "safety_score": min(100, safety_score),
            "performance_overhead_pct": profile["estimated_overhead_pct"],
            "suggestions": suggestions if suggestions else ["当前配置安全等级良好"],
        }