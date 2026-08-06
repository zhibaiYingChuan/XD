from __future__ import annotations
# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白
# 本文件受道体研究许可证 v1.0 约束，禁止逆向工程和再分发
# 详见 LICENSE 文件

# Implements §2.1 配置对象 XuanDunConfig — 道体动态活性架构

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

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
    """道体玄盾全局配置对象。

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

    # 洛书三阶段自适应学习策略（出厂→影子缓冲→稳态微调）
    # — 出厂阶段(A)：仅使用静态 benign_v1.npy，不做任何在线写入
    # — 影子缓冲阶段(B)：前 N 条用户流量写入 Shadow Buffer，仅用于计算领域偏移校正查询向量
    # — 稳态阶段(C)：达到阈值后，以低学习率对动态簇心做 EMA 微调
    luoshu_shadow_buffer_offset_ratio: float = 0.3   # B阶段 领域偏移校正倍率（原写死0.3，现可外部调参）
    luoshu_shadow_buffer_capacity: int = 200          # Shadow Buffer 最大容量（deque maxlen）
    luoshu_shadow_update_every: int = 10              # B阶段 每收到多少条就重算一次领域偏移
    luoshu_shadow_min_for_shift: int = 50             # B阶段 Shadow Buffer 至少累积多少条才首次启用校正
    luoshu_phase_c_start_count: int = 1000            # 累计学习样本 ≥ 此值 进入稳态 C 阶段
    luoshu_steady_state_learning_rate: float = 0.01   # C阶段 EMA 微调学习率（极低防抖动）
    # 抗毒化（Anti-Poisoning）保护：
    #   要加入动态安全原型的向量，若与已有攻击原型的最近距离 < 此阈值，视为“伪装良性毒化样本”，拒绝学习
    #   0.0 = 关闭  →  1.0 = 任何近邻都拒绝  →  推荐 0.80~0.92 之间
    luoshu_poisoning_similarity_threshold: float = 0.88
    # 四元组攻击相似度冷启动门槛
    # 出厂 warmup 只有 8 条攻击短种子 + 25 条安全句子，统计严重失真
    # 拒绝样本 < 此值 或 域内 4-gram 种类数 < 500 时禁用 fourgram_signal，防系统性误报
    # 同时需配合"仅真攻击信号触发才更新 rejected_fourgram_profile"机制，防止正反馈循环
    fourgram_min_rejected_samples: int = 200

    # ── 合法自然语言豁免边界参数（原写死在_is_natural_language_text中的硬编码）──
    #   防止纯JSON数据包、德文长句、中英混杂编程注释等跳出[2.5,6.8]区间导致豁免失效
    #   出厂默认值针对中文+英文优化，其他语域可在部署时调整
    natural_lang_printable_ratio_threshold: float = 0.90  # 可打印自然语言字符占比 ≥ 此值才判定为自然语言
    natural_lang_entropy_low: float = 2.5                # Shannon字节熵下限（低于此值视为：全重复字符/压缩前报文）
    natural_lang_entropy_high: float = 6.8               # Shannon字节熵上限（高于此值视为：Base64/Hex/加密编码）

    # 抗毒化保护：稳态EMA微调 总更新次数绝对上限
    #   脉冲式攻击（1000条×1天）由 _steady_updates_in_window 防住
    #   慢性式攻击（100条×10天×3个簇心/天 = 30天后毒化成功）由此绝对上限防住
    #   默认 500 次：出厂 50 静态簇心 × 10 次/簇心的微调余量，用完后永久锁死动态簇心不再接受在线学习
    luoshu_poisoning_total_updates_cap: int = 500

    # 抗毒化保护：单个稳态周期（T=100条）内最多允许更新多少个原型簇心，防止批量注入短期覆盖全局
    luoshu_poisoning_max_updates_per_hundred: int = 3

    # ── 输出护栏（Output Guardrail）：
    #   在模型输出侧检测违规内容，形成"输入检测 + 输出护栏"的双向闭环。
    #   复用洛书映射器 encode 做语言无关编码，但使用输出侧独立原型库（安全/违规），
    #   与输入侧原型隔离，避免相互污染（节 9.5 独立评测集 test_outputs_v1）。
    #   三级处置（节 9.1）：high→拦截 / medium→打码替换 / low→仅告警。
    enable_output_guardrail: bool = True   # 是否启用输出护栏
    # 攻击距离分级阈值（distance 越小越危险，由 compute_attack_distance 产出）
    output_guardrail_high_threshold: float = float(secure_value("output_guardrail_high_threshold", "0.30"))    # 攻击距离 < 此值 → 高危拦截
    output_guardrail_medium_threshold: float = float(secure_value("output_guardrail_medium_threshold", "0.45"))  # 攻击距离 < 此值 → 中危打码
    output_guardrail_low_threshold: float = float(secure_value("output_guardrail_low_threshold", "0.60"))        # 攻击距离 < 此值 → 低危告警
    # 安全距离豁免阈值：安全距离 < 此值 时优先放行，防止正常输出（医学术语/代码）被误拦
    output_guardrail_safe_exempt: float = float(secure_value("output_guardrail_safe_exempt", "0.20"))
    # 打码替换占位符（节 9.1 中危处置）
    output_guardrail_redact_token: str = "[REDACTED]"
    # 输出侧原型库容量上限（独立于输入侧，防原型洪水）
    output_guardrail_prototype_max: int = 256
    # 违规模式信号（规则检测，回归融合权重）：
    #   洛书语义距离区分度有限，纯空间距离无法可靠识别"系统提示词/密钥泄露"等违规输出。
    #   因此融合"违规模式信号"（正则+特征词，见 _check_output._compute_rule_signal）。
    #   以下为三类违规模式信号的触发阈值（0~1，值越高越危险）。
    output_guardrail_rule_block_signal: float = float(secure_value("output_guardrail_rule_block_signal", "0.80"))    # 模式信号 ≥ 此值 → 高危险，直接拦截
    output_guardrail_rule_medium_signal: float = float(secure_value("output_guardrail_rule_medium_signal", "0.50"))  # 模式信号 ≥ 此值 → 中危险，打码

    # 时序一致性校验
    enable_timing_check: bool = True
    max_window_size: int = 32
    anomaly_threshold: float = 2.0
    state_ttl: int = 3600
    timing_ewma_alpha: float = 0.1       # 时序 EWMA 平滑系数
    timing_threshold_floor: float = 0.5   # 时序阈值硬下限
    # 会话管理（LRU 淘汰 / TTL 过期）
    max_sessions: int = 10000             # 最大会话数，超限 LRU 淘汰
    session_ttl: int = 7200               # 会话过期时间（秒）

    # 会话级信任度衰减（trust_decay）与意图漂移（intent_drift）—— 多轮对话状态跟踪
    #   trust 初始=1.0（最高信任），每轮按 decay_rate 指数衰减，不低于 trust_floor。
    #   trust 仅反映"静默衰减"，实际风险升级由 intent_drift 触发。
    session_trust_decay_rate: float = 0.95    # 每轮信任度保留率（0.95 表示衰减 5%）
    session_trust_floor: float = 0.30          # 信任度硬下限（不降至 0，避免长期对话被无限降权）
    # 意图漂移：马氏距离偏离会话历史 EWMA 的 σ 倍数，超过 drift_sigma_threshold 视为意图突变
    session_intent_drift_sigma: float = 2.5    # 漂移阈值：距离偏离 EWMA 均值 > 2.5σ → 触发
    session_intent_drift_min_turns: int = 6    # 前 N 轮统计不足时不触发漂移判定（避免冷启动误报）

    # 侧信道防御
    side_channel_delay: bool = False       # 是否启用随机延迟掩码（抗时序分析）
    side_channel_delay_us: int = 500      # 随机延迟范围（微秒），实际延迟在 [0, max] 均匀分布

    # 边界枚举防御
    prototype_distance_noise: float = 0.0  # 原型距离噪声标准差，模糊边界防枚举
    prototype_projection_scale: float = 0.0  # 高维随机投影扰动强度，0=关闭，推荐 0.01~0.05

    # 全局速率限制 + 无限消耗防护（节 9.x：资源耗尽攻击防御）
    global_qps_limit: int = 0              # 全局 QPS 上限，0 表示不限
    max_request_length: int = 8000         # 单请求字符长度上限（超长直接拦截，防超大输入耗显存）
    session_quota_per_minute: int = 60     # 会话每分钟配额（按 session_id 限流），0=不限
    session_quota_per_hour: int = 1000     # 会话每小时配额（按 session_id 限流），0=不限

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

    # 敏感信息泄露防护（节 9.7：PII / 密钥 / 企业自定义词典）
    #   high→流水线直接 REJECT，medium→对输出打码 [REDACTED:<cat>]，low→仅告警（不影响放行）
    enable_sensitive_leak: bool = True                # 是否启用敏感信息检测
    sensitive_high_block: bool = True                 # 命中 high 级别 → 流水线拦截（reject_stage=sensitive_leak）
    sensitive_medium_redact: bool = True              # 命中 medium 级别 → 对 final_output 打码（不拦截）
    sensitive_low_alert_only: bool = True             # 命中 low 级别 → 仅在 debug_info 标注（不拦截不打码）
    sensitive_dict_path: Optional[str] = None         # 企业自定义词典持久化路径（None → {XUANDUN_DATA_DIR}/sensitive_dict.json）

    # 间接提示注入防护（节 9.8：Indirect Prompt Injection）
    #   检测用户prompt中嵌入的「外部内容围栏 + 围栏内部恶意指令」组合（RAG/邮件/网页摘要场景）
    #   阈值越高越严格；默认 ≥3.0 拦截，≥2.0 仅告警
    enable_external_injection_check: bool = True      # 是否启用间接提示注入检测
    external_injection_block_threshold: float = 3.5   # 累计反指令特征分 ≥ 此值 → 流水线拦截（reject_stage=external_injection）
    external_injection_warn_threshold: float = 2.0    # ≥ 此值 → 打标 sanitize_text 入 debug_info（不拦截）
    external_injection_sanitize: bool = True          # 命中 warn 且未拦截时，在 debug_info 输出脱敏后的安全文本

    # 系统提示泄露升级检测（节 9.9：Prompt Leak — 洛书语义分类 + 置信度）
    #   超越纯关键词组合（旧 detect_system_prompt_leak 只有 bool），
    #   用洛书语义距离 + 组合特征分输出置信度，分级处置。
    enable_prompt_leak_check: bool = True             # 是否启用系统提示泄露语义检测
    prompt_leak_block_min: float = 0.75               # 置信度 ≥ 此值 → 流水线拦截（reject_stage=prompt_leak）
    prompt_leak_warn_min: float = 0.70                # 置信度 ≥ 此值 → 打标入 debug_info（不拦截）
    prompt_leak_use_luoshu: bool = True               # 是否用洛书语义距离增强置信度
    min_samples_for_switch: int = 1000      # 自动切换到保护模式所需的最小正常样本数
    enable_builtin_attacks: bool = True     # 启用内置攻击样本（让洛书攻击原型库从一开始就不为空）

    # 企业级运维（逃生通道 + 灰度部署）
    emergency_bypass: bool = False           # 逃生通道：开启后所有请求直接放行，不经过任何检测
    gray_deploy_ratio: float = 1.0           # 灰度部署比例：0.0~1.0，表示实际拦截的请求比例（1.0=全量拦截）

    # 双层架构（外门快速拒绝 + 内门精判学习）
    enable_dual_layer: bool = True           # 启用双层架构：外门先快速筛选，不确定的送入内门深度分析
    outer_learned_cache_size: int = 500      # 外门学习缓存大小（从内门反馈的攻击/安全模式哈希数）

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
                # P1-1 修复：生产环境强制要求安全密钥，禁止使用 fallback key
                if os.environ.get('XUANDUN_REQUIRE_SECURE_KEY', '') == '1':
                    raise RuntimeError("Production environment requires secure key, but fallback shell_key is being used")
                sys.stderr.write("[XuanDun] WARNING: XUANDUN_SHELL_KEY not set, using insecure fallback key\n")
                self.shell_key = b"daoti_xuandun_16"
        if self.mapping_key is None:
            env_key = os.environ.get("XUANDUN_MAPPING_KEY")
            if env_key:
                self.mapping_key = env_key.encode("utf-8")
            else:
                import sys
                # P1-1 修复：生产环境强制要求安全密钥，禁止使用 fallback key
                if os.environ.get('XUANDUN_REQUIRE_SECURE_KEY', '') == '1':
                    raise RuntimeError("Production environment requires secure key, but fallback mapping_key is being used")
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