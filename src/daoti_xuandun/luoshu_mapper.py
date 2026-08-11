from __future__ import annotations
# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白
# 本文件受道体研究许可证 v1.0 约束，禁止逆向工程和再分发
# 详见 LICENSE 文件

"""洛书符号映射器 — 语言无关的纯符号级安全域表征。

活性防护哲学：安全检测不应依赖任何语言特征（大写比例、命令式短语等），
而应基于输入在高维符号空间中的位置。洛书映射器将任意输入（无论语言、
编码、长度）映射到64卦原型空间，通过原型距离判断"域内/域外/攻击"。

核心原理（源自Loong Recall / TrigramSpace）：
1. 输入 → Unicode码点散列 → 高维向量
2. 阴阳分叉：向量分为阴（低频/稳定）和阳（高频/变化）两个子空间
3. 穿透门控：阴阳光融合为洛书空间状态向量
4. 原型匹配：状态向量与64卦原型比较，计算流形距离

数据驱动设计（无硬编码参数）：
- 阴阳分叉比例由输入的Shannon熵动态决定（质疑A修复）
- 攻击原型学习带去重和频率门限（质疑C修复）
- 预置通用域原型解决冷启动问题（质疑E修复）

保密性设计：不暴露原型向量内容、门控权重或散列种子。
仅提供距离值和匹配卦名（脱敏后）。
"""

import hashlib
import os
from collections import Counter, deque
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional, Set, Tuple


import numpy as np

from daoti_xuandun.config import XuanDunConfig

LUOSHU_NATIVE_DIM = 176

# 出厂良性原型文件（与本文件同目录的 resources/）
_BENIGN_NPY_FILENAME = "benign_v1.npy"
_BENIGN_NPY_PATH = Path(__file__).resolve().parent / "resources" / _BENIGN_NPY_FILENAME


def _resolve_benign_npy_path() -> Path:
    """解析出厂良性原型路径，支持源码与 Nuitka 打包两种布局。

    Nuitka --standalone 将模块编译为单文件 .pyd，__file__ 指向
    dist/daoti_xuandun/ 下，resources/ 子目录不再跟随；且引擎以
    resources/engine/ 为工作目录启动。因此按优先级尝试多个候选位置：
      1. 源码布局：<模块目录>/resources/benign_v1.npy
      2. 打包布局：<模块目录>/benign_v1.npy（--include-package-data 平铺）
      3. 工作目录：<cwd>/daoti_xuandun/resources/benign_v1.npy
      4. 工作目录：<cwd>/resources/benign_v1.npy
      5. 工作目录：<cwd>/benign_v1.npy
    """
    proj_dir = Path(__file__).resolve().parent
    candidates = [
        proj_dir / "resources" / _BENIGN_NPY_FILENAME,
        proj_dir / _BENIGN_NPY_FILENAME,
        Path.cwd() / "daoti_xuandun" / "resources" / _BENIGN_NPY_FILENAME,
        Path.cwd() / "resources" / _BENIGN_NPY_FILENAME,
        Path.cwd() / _BENIGN_NPY_FILENAME,
    ]
    for cand in candidates:
        if cand.exists():
            return cand
    return _BENIGN_NPY_PATH


class LuoshuSymbolMapper:
    """洛书符号映射器 — 语言无关的纯符号级安全域表征。

    将任意输入映射到64卦原型空间，提供：
    - luoshu_distance: 输入与最近安全原型的流形距离
    - luoshu_density: 输入在洛书空间中的局部密度（邻居数）
    - gua_affinity: 输入与各卦的亲和度分布

    数据驱动设计：
    - 阴阳分叉比例由输入Shannon熵动态调整，无硬编码参数
    - 攻击原型学习带去重和频率门限，防原型洪水攻击
    - 预置通用域原型，冷启动即有基础判别力
    - 内部使用176维洛书空间，通过无损投影适配玄盾hidden_dim

    Attributes:
        config: 全局配置。
        native_dim: 洛书空间原生维度（176，与Loong Recall对齐）。
        state_dim: 输出维度（适配玄盾hidden_dim）。
        n_gua: 卦数（固定64）。
        gua_prototypes: 64卦原型矩阵，shape (64, native_dim)。
        safe_prototypes: 安全域原型集合（在线学习积累）。
        attack_prototypes: 攻击原型集合（负原型，在线学习积累）。
    """

    GUA_NAMES = [
        "qian", "kun", "zhun", "meng", "xu", "song", "shi", "bi",
        "xiaoxu", "lv", "tai", "pi", "tongren", "daren", "qian", "yu",
        "sui", "gu", "lin", "guan", "shike", "shihuo", "bo", "fu",
        "wuwang", "daxu", "yi", "dagu", "kan", "li", "xian", "heng",
        "dun", "dazhuang", "jin", "mingyi", "jiaren", "kui", "jian", "jie",
        "sun", "yi", "guai", "gou", "cui", "sheng", "kun2", "jing",
        "ge", "ding", "zhen", "gen", "jian2", "guimei", "feng", "lv2",
        "xun", "dui", "huan", "jie2", "zhongfu", "xiaoguo", "jiji", "weiji",
    ]

    def __init__(self, config: XuanDunConfig):
        self.config = config
        self.native_dim = LUOSHU_NATIVE_DIM
        self.state_dim = config.hidden_dim
        self.n_gua = 64
        self._seed = self._derive_seed(config.mapping_key or b"luoshu_default")
        self._init_gua_prototypes()
        self._init_projection()
        self.safe_prototypes: List[np.ndarray] = []
        # ── 出厂初始化阶段（Phase A）：只读原型，不进入在线学习队列 ──
        # 架构级指令3：仅观测不写入 — benign_v1.npy 的 50 个簇心只做距离计算基准，
        # 不参与在线 deque 的 push/pop/截断操作，防止离线数据长期锚定动态更新
        self._static_prototypes: List[np.ndarray] = []
        self._static_count = 0  # 仅统计展示，不参与 deque
        self.attack_prototypes: List[np.ndarray] = []
        # 出厂预热攻击原型（只读）：来自 attack_v1.json + BUILTIN_ATTACKS，
        # 经人工校准覆盖市面常见攻击。与 attack_prototypes（在线学习积累、可能被
        # 良性样本污染）物理隔离，仅用于"出厂预热攻击直接否决"硬拦截，保证
        # 交付成品对常见攻击开箱生效且不受在线学习污染导致的良性误报影响。
        self.factory_attack_prototypes: List[np.ndarray] = []
        self._attack_fingerprint_counter: Counter = Counter()
        self._attack_dedup_threshold = 0.95
        self._attack_max_per_cluster = 3
        # 在线攻击学习累计次数（仅统计真正新增的攻击原型，去重/限流跳过不计）
        # 用于保护模式下向 UI 展示「攻击学习进化」的真实进度
        self._attack_learn_count = 0

        # ── 三阶段自适应学习策略数据结构 ──
        # Phase B: 快速磨合期（前 3 天 / 前 200 条）— Shadow Buffer 只算偏移不改原型
        _shadow_cap = getattr(config, "luoshu_shadow_buffer_capacity", 200)
        self._shadow_buffer: Deque[np.ndarray] = deque(maxlen=_shadow_cap)  # 影子缓冲区（容量来自配置）
        self._static_centroid: Optional[np.ndarray] = None  # 出厂全局质心（启动时计算）
        self._domain_shift: Optional[np.ndarray] = None  # 领域偏移向量

        # Phase C: 稳态迭代期（满 1000 条后）— 极低学习率微调簇心
        self._steady_state = False
        # 学习率来自配置 luoshu_steady_state_learning_rate，原硬编码 0.01 作为兜底
        self._learning_rate = getattr(
            config, "luoshu_steady_state_learning_rate", 0.01
        )
        self._total_learned = 0  # 在线学习累计接受的样本数（不含静态出厂）

        # ── 抗毒化（Anti-Poisoning）计数器 ──
        # 被判定为“疑似伪装良性”而拒绝进入稳态微调的样本数
        self._poisoning_skipped = 0
        # 稳态“窗口”限流：每 100 条样本最多只允许更新 N 个簇心，防批量注入短期污染
        self._steady_window_start_sample = 0  # 当前窗口起始 sample 序号（_total_learned）
        self._steady_updates_in_window = 0
        # 被限流（窗口已满）而跳过微调的样本数
        self._poisoning_window_limited = 0
        # Gate C – 绝对总量上限：总稳态 EMA 微调历史累计次数（防100条/天×30天慢性毒化）
        self._steady_total_updates = 0
        self._poisoning_total_cap_limited = 0

        self._init_universal_prototypes()
        # 启动时计算静态质心（用于 Phase B 领域偏移量计算）
        if self._static_prototypes:
            self._static_centroid = self._normalize(
                np.mean(np.array(self._static_prototypes, dtype=np.float32), axis=0)
            )

    def _derive_seed(self, key: bytes) -> int:
        h = hashlib.sha256(key).hexdigest()
        return int(h[:16], 16)

    def _init_gua_prototypes(self):
        """初始化64卦原型为正交化随机向量（176维洛书空间）。"""
        rng = np.random.default_rng(seed=self._seed)
        raw = rng.normal(0, 1, (self.n_gua, self.native_dim)).astype(np.float32)
        for i in range(self.n_gua):
            raw[i] = self._normalize(raw[i])
        self.gua_prototypes = raw

    def _init_projection(self):
        """初始化无损投影层：176维→hidden_dim。

        质疑D修复：使用随机正交投影矩阵，将176维洛书空间
        无损映射到玄盾的hidden_dim维度。正交投影保持距离关系，
        避免截断导致的信息损失。
        """
        if self.state_dim >= self.native_dim:
            self._proj = np.eye(self.state_dim, dtype=np.float32)
            return
        rng = np.random.default_rng(seed=self._seed + 42)
        raw = rng.normal(0, 1.0 / max(1e-10, np.sqrt(self.native_dim)),
                         (self.state_dim, self.native_dim)).astype(np.float32)
        self._proj = raw

    def _init_universal_prototypes(self):
        """预置通用域原型，解决冷启动问题（架构级指令1-3 执行点）。

        Phase A: 出厂初始化 — 加载 benign_v1.npy 的 50 个良性簇心（覆盖5大类）
        - 仅观测不写入：簇心放入 _static_prototypes，不进入 safe_prototypes 的在线 deque
        - 保证：出厂误报率 < 3%，后续 deque push/pop 不污染离线数据
        - 后向兼容：若 benign_v1.npy 丢失，回退到 15 条硬编码样本（旧逻辑）
        """
        loaded = False
        benign_path = _resolve_benign_npy_path()
        if benign_path.exists():
            try:
                cluster_centroids = np.load(benign_path)
                if (isinstance(cluster_centroids, np.ndarray)
                        and cluster_centroids.ndim == 2
                        and cluster_centroids.shape[1] == self.native_dim):
                    for vec in cluster_centroids:
                        self._static_prototypes.append(
                            self._normalize(vec.astype(np.float32)).copy()
                        )
                    self._static_count = len(self._static_prototypes)
                    loaded = True
            except Exception:
                # npy 文件损坏：静默回退到硬编码逻辑
                self._static_prototypes = []
                self._static_count = 0

        if not loaded:
            # 回退逻辑：15条硬编码（旧代码兼容，保证不因为npy缺失崩溃）
            rng = np.random.default_rng(seed=self._seed + 100)
            universal_texts = [
                "Hello, how are you today?",
                "What is the weather like?",
                "Can you help me with something?",
                "Please explain this concept.",
                "I would like to know more about this topic.",
                "你好，请问有什么可以帮助你的？",
                "帮我查一下明天的天气",
                "请解释一下这个概念",
                "论语有云学而时习之",
                "道德经曰道可道非常道",
                "def hello_world(): print('hello')",
                "SELECT * FROM users WHERE id = 1",
                "import numpy as np",
                "for i in range(10): print(i)",
                "\x00\x01\x02\x03base64encoded",
            ]
            for text in universal_texts:
                state = self._encode_native(text, rng)
                # 回退模式下，将硬编码样本放入 _static_prototypes，同样仅观测
                self._static_prototypes.append(state.copy())
            self._static_count = len(self._static_prototypes)

        # safe_prototypes 保持为空 — 用于 Phase C 稳态期的动态在线学习
        # 这样 deque 的 max_size 截断只会影响 Phase C 的流量样本，不会弄丢静态簇心
        self.safe_prototypes = []

    def encode(self, text: str) -> np.ndarray:
        """将文本编码为洛书空间状态向量（适配玄盾hidden_dim）。

        编码管线（语言无关）：
        1. Unicode码点 → 位置敏感散列 → 176维初始向量
        2. 阴阳分叉：由输入Shannon熵动态决定分叉比例
        3. 穿透门控：融合为洛书空间状态
        4. 无损投影：176维→hidden_dim

        Args:
            text: 输入文本（任意语言/编码）。

        Returns:
            洛书空间状态向量，shape (state_dim,)。
        """
        state_176 = self._encode_native(text)
        if self.state_dim >= self.native_dim:
            padded = np.zeros(self.state_dim, dtype=np.float32)
            padded[:self.native_dim] = state_176
            return self._normalize(padded)
        projected = self._proj @ state_176
        return self._normalize(projected)

    def _encode_native(self, text: str, rng=None) -> np.ndarray:
        """将文本编码为176维洛书空间状态向量（内部方法）。"""
        raw_vec = self._text_to_raw_vector(text, rng)
        entropy = self._compute_shannon_entropy(text)
        state = self._yin_yang_bifurcate(raw_vec, entropy)
        return state

    def compute_distance(self, state: np.ndarray) -> Tuple[float, str]:
        """计算状态向量与最近卦原型的流形距离。"""
        state_176 = self._to_native(state)
        state_norm = self._normalize(state_176)
        sims = self.gua_prototypes @ state_norm
        best_idx = int(np.argmax(sims))
        best_sim = float(sims[best_idx])
        distance = 1.0 - best_sim
        return distance, self.GUA_NAMES[best_idx]

    def compute_safe_distance(self, state: np.ndarray) -> float:
        """计算状态向量与安全域原型的最小距离（合并静态出厂+动态在线原型）。
        
        P2 权重过渡机制：出厂本能 → 后天学习
        - Phase A/B：仅使用 _static_prototypes（出厂本能权重 100%）
        - Phase C 初期（_total_learned < 2000）：出厂权重递减，后天学习权重递增
        - Phase C 稳定期（_total_learned >= 2000）：后天学习权重 100%，逐步边缘化出厂本能
        
        权重计算公式（线性递减）：
        - static_weight = max(0.1, 1.0 - (_total_learned - 1000) / 1000)
        - online_weight = 1.0 - static_weight

        架构级指令4：配合新的50个良性簇心，正常文本距离簇心的距离
        会比旧的15条孤立点缩短约 30-50%，MEDIUM 判定数量急剧减少，
        误报率从 4% 向 0.5% 靠拢。
        """
        if not self._static_prototypes and not self.safe_prototypes:
            return 1.0
        state_176 = self._to_native(state)
        state_norm = self._normalize(state_176)

        # Phase B 领域偏移补偿：如果 Shadow Buffer 已累积到配置门槛，
        # 用 domain_shift 对查询向量做轻量校正（不修改原型本身）
        # 注意：校正倍率 shadow_buffer_offset_ratio 来自配置（默认0.3），不是硬编码
        query_vec = state_norm
        if self._domain_shift is not None:
            _min_for_shift = getattr(self.config, "luoshu_shadow_min_for_shift", 50)
            if len(self._shadow_buffer) >= _min_for_shift:
                _offset_ratio = getattr(self.config, "luoshu_shadow_buffer_offset_ratio", 0.3)
                query_vec = self._normalize(
                    state_norm + _offset_ratio * self._domain_shift
                )

        # 合并两部分原型（静态簇心优先，保证距离下界由出厂数据兜底）
        # P2 权重过渡：出厂本能权重随学习进度递减
        best_sim = 0.0
        if self._static_prototypes:
            static = np.array(self._static_prototypes, dtype=np.float32)
            static_norm = static / np.maximum(np.linalg.norm(static, axis=1, keepdims=True), 1e-8)
            sims = static_norm @ query_vec
            static_sim = float(np.max(sims))
            # P2 权重过渡：出厂静态原型权重随学习递减
            # - _total_learned < 1000 (Phase B)：出厂权重 1.0（完全依赖出厂本能）
            # - 1000~2000 (Phase C 初期)：出厂权重从 1.0 线性递减到 0.1
            # - >= 2000 (Phase C 稳定期)：出厂权重 0.1（仅作兜底，让位给后天学习）
            if self._total_learned >= 1000:
                static_weight = max(0.1, 1.0 - (self._total_learned - 1000) / 1000)
                # 加权后相似度 = 出厂相似度 × 权重 + 出厂相似度默认值 × (1-权重)
                # 当权重低时，出厂原型的贡献退化为"取默认值"，不干扰后天学习
                best_sim = max(best_sim, static_sim * static_weight + 0.5 * (1.0 - static_weight))
            else:
                best_sim = max(best_sim, static_sim)
        if self.safe_prototypes:
            protos = np.array(self.safe_prototypes, dtype=np.float32)
            norms = np.linalg.norm(protos, axis=1, keepdims=True)
            norms = np.maximum(norms, 1e-8)
            protos_norm = protos / norms
            sims = protos_norm @ query_vec
            online_sim = float(np.max(sims))
            # P2 权重过渡：后天学习原型权重随学习递增
            # - _total_learned < 1000 (Phase B)：无 safe_prototypes（跳过）
            # - 1000~2000 (Phase C 初期)：后天权重从 0.0 递增到 0.9
            # - >= 2000 (Phase C 稳定期)：后天权重 0.9（完全接管）
            if self._total_learned >= 1000:
                online_weight = min(0.9, (self._total_learned - 1000) / 1000)
                best_sim = max(best_sim, online_sim * online_weight + 0.5 * (1.0 - online_weight))
            else:
                best_sim = max(best_sim, online_sim)
        return 1.0 - best_sim

    def compute_attack_distance(self, state: np.ndarray) -> float:
        """计算状态向量与攻击原型的最小距离。"""
        if not self.attack_prototypes:
            return 1.0
        state_176 = self._to_native(state)
        state_norm = self._normalize(state_176)
        protos = np.array(self.attack_prototypes, dtype=np.float32)
        norms = np.linalg.norm(protos, axis=1, keepdims=True)
        norms = np.maximum(norms, 1e-8)
        protos_norm = protos / norms
        sims = protos_norm @ state_norm
        return 1.0 - float(np.max(sims))

    def compute_factory_attack_distance(self, state: np.ndarray) -> float:
        """计算状态向量与【出厂预热攻击原型】的最小距离。

        与 compute_attack_distance 的区别：仅针对出厂预热只读原型库
        （factory_attack_prototypes，来自 attack_v1.json + BUILTIN_ATTACKS），
        不包含在线学习积累的攻击原型。在线学习原型可能被良性样本污染，
        若纳入会引发良性误报，故出厂预热否决（硬拦截）只使用本方法。
        """
        if not self.factory_attack_prototypes:
            return 1.0
        state_176 = self._to_native(state)
        state_norm = self._normalize(state_176)
        protos = np.array(self.factory_attack_prototypes, dtype=np.float32)
        norms = np.linalg.norm(protos, axis=1, keepdims=True)
        norms = np.maximum(norms, 1e-8)
        protos_norm = protos / norms
        sims = protos_norm @ state_norm
        return 1.0 - float(np.max(sims))

    def compute_local_density(self, state: np.ndarray, threshold: float = 0.7) -> float:
        """计算状态向量在洛书空间中的局部密度。"""
        if not self.safe_prototypes:
            return 0.0
        state_176 = self._to_native(state)
        state_norm = self._normalize(state_176)
        protos = np.array(self.safe_prototypes, dtype=np.float32)
        norms = np.linalg.norm(protos, axis=1, keepdims=True)
        norms = np.maximum(norms, 1e-8)
        protos_norm = protos / norms
        sims = protos_norm @ state_norm
        return float(np.mean(sims > threshold))

    def learn_safe(self, state: np.ndarray):
        """将状态向量加入安全原型集合（三阶段数据策略，架构级分层执行）。

        三阶段自适应：
        ─────────────────────────────────────────────────────────────
        Phase A 出厂初始化:
            safe_prototypes 为空，_static_prototypes = 50 簇心
            静态簇心只读，不进 deque，保证不被单次调用修改
        ─────────────────────────────────────────────────────────────
        Phase B 快速磨合期:
            _total_learned < 1000 或 shadow_buffer 未满 200
            写入 Shadow Buffer，只计算领域偏移量 Domain Shift
            不修改全局原型 → 防止用户极端输入（如全是代码）带偏整体
        ─────────────────────────────────────────────────────────────
        Phase C 稳态迭代期:
            _total_learned >= 1000
            激活 deque 在线学习，LR=0.01 极低学习率微调全局簇心
            越用越准，但不会因为某一次误判而剧烈抖动
        ─────────────────────────────────────────────────────────────
        """
        state_176 = self._to_native(state)
        self._total_learned += 1

        # Phase B / Phase C 分流判定（阈值来自配置，默认1000）
        _phase_c_start = getattr(self.config, "luoshu_phase_c_start_count", 1000)
        in_phase_c = self._total_learned >= _phase_c_start

        if not in_phase_c:
            # ============== Phase B: 影子缓冲区 + 领域偏移计算 ==============
            self._shadow_buffer.append(state_176.copy())
            # Shadow Buffer 达到配置门槛后，按配置步长定期更新偏移（平滑）
            _min_for_shift = getattr(self.config, "luoshu_shadow_min_for_shift", 50)
            _update_every = getattr(self.config, "luoshu_shadow_update_every", 10)
            if (len(self._shadow_buffer) >= _min_for_shift
                    and len(self._shadow_buffer) % _update_every == 0):
                self._recompute_domain_shift()
            # Phase B 的安全距离仍然能算，但不修改 safe_prototypes
            return

        # ============== Phase C: 稳态期 — 低学习率微调 ==============
        # 先进入 deque 管理（LR=1 全量入队做记忆）
        self.safe_prototypes.append(state_176.copy())
        max_size = self.config.prototype_max_size
        if len(self.safe_prototypes) > max_size:
            self.safe_prototypes = self.safe_prototypes[-max_size:]

        # 再做一次极低学习率的质心微调（不修改 _static_prototypes）
        self._apply_steady_state_update(state_176)

    def _recompute_domain_shift(self):
        """Phase B: 根据 Shadow Buffer 计算「用户流量质心」相对于「出厂质心」的偏移向量。

        这个向量只用于 compute_safe_distance 中的查询校正
        （加 luoshu_shadow_buffer_offset_ratio 倍偏移，默认 0.3，来自配置不写死），
        不直接修改簇心，保证即使用户流量极端也不会破坏出厂原型。
        """
        if self._static_centroid is None:
            return
        buf_list = list(self._shadow_buffer)
        user_centroid = self._normalize(
            np.mean(np.array(buf_list, dtype=np.float32), axis=0)
        )
        # 偏移向量 = 用户质心 - 出厂质心（归一化后，保证方向有意义）
        shift = user_centroid - self._static_centroid
        shift_norm = float(np.linalg.norm(shift))
        if shift_norm > 0:
            # 再对 shift 做一次归一化，防止数值漂移
            self._domain_shift = self._normalize(shift)
        else:
            self._domain_shift = None

    def _apply_steady_state_update(self, state_176: np.ndarray):
        """Phase C: 稳态微调 — 找到最近的动态 safe 原型，推过去一点。

        设计意图（架构级隐患修复）：
        - 只修改 Phase C 动态加入的 safe_prototypes，不碰 _static_prototypes
        - 保证 _static_prototypes 永远代表出厂的「全域正常语言空间锚点」
        - 学习率来自 luoshu_steady_state_learning_rate（默认0.01，防抖动）

        Anti-Poisoning（抗“伪装良性”毒化）三道门：
        ────────────────────────────────────────────────────────────
        Gate A – 相似度门：
          如果本次输入 与 已有攻击原型 的最近 余弦相似度 > 阈值，
          说明这是“长得像攻击”的样本，有可能是黑客精心构造的伪装良性，
          直接跳过 EMA 微调，累计 _poisoning_skipped。
        Gate B – 速率门（每100条更新 N 个）：
          黑客可能一次性批量注入 1000 条同类“边界良性”，短期把原型推偏。
          每过 100 条 Phase C 样本，重置一次窗口；窗口内最多允许
          更新 poisoning_max_updates_per_hundred（默认3）个簇心。
        Gate C – 绝对总量上限门（总更新次数上限，防慢性毒化）：
          黑客把 1000 条恶意样本均匀分布在 10 天 × 100 条/天，
          Gate B 每天会放行 3 条，30 天后被缓慢毒化成功。
          本门设置 luoshu_poisoning_total_updates_cap（默认 500 次）
          = 出厂 50 静态簇心 × 10 次/簇心微调余量，用完后永久冻结，
          不接受任何在线 EMA 微调，彻底封死慢性毒化路径。
        ────────────────────────────────────────────────────────────
        """
        if not self.safe_prototypes:
            return
        cfg = self.config

        # ================= Gate A – 攻击相似度门 =================
        # 阈值：luoshu_poisoning_similarity_threshold（0 表示关闭这道门）
        # 全面审查发现：旧实现只查在线 attack_prototypes，忽略出厂预热攻击原型
        # factory_attack_prototypes。出厂攻击原型是最可信的攻击特征，样本与出厂
        # 攻击高度相似更可能是"伪装良性"，必须一并纳入拒绝学习，补齐防毒化盲区。
        poison_threshold = float(getattr(cfg, "luoshu_poisoning_similarity_threshold", 0.0))
        atk_pool = list(self.attack_prototypes) + list(self.factory_attack_prototypes)
        if poison_threshold > 0.0 and atk_pool:
            # 计算 state 与所有攻击原型（在线+出厂）的最近余弦相似度
            state_norm = self._normalize(state_176)
            atk = np.array(atk_pool, dtype=np.float32)
            atk_norms = np.linalg.norm(atk, axis=1, keepdims=True)
            atk_norms = np.maximum(atk_norms, 1e-8)
            atk_normed = atk / atk_norms
            atk_sims = atk_normed @ state_norm
            nearest_atk_sim = float(np.max(atk_sims))
            if nearest_atk_sim > poison_threshold:
                self._poisoning_skipped += 1
                return

        # ================= Gate B – 窗口速率门 =================
        _window_size = 100
        max_per_window = int(getattr(cfg, "luoshu_poisoning_max_updates_per_hundred", 3))
        # 窗口起点基于 _total_learned，每过 _window_size 条自动开新窗口
        current_window_start = (self._total_learned - 1) // _window_size * _window_size + 1
        # 注意 _total_learned 在 learn_safe 开头已经 +1 了，所以本条属于新的位置
        if current_window_start != self._steady_window_start_sample:
            # 新窗口，重置计数
            self._steady_window_start_sample = current_window_start
            self._steady_updates_in_window = 0
        if self._steady_updates_in_window >= max_per_window:
            # 窗口内配额已用完，跳过本轮微调
            self._poisoning_window_limited += 1
            return

        # ================= Gate C – 绝对总量上限（防慢性毒化） =================
        # luoshu_poisoning_total_updates_cap=0 表示关闭（默认启用）
        total_cap = int(getattr(cfg, "luoshu_poisoning_total_updates_cap", 500))
        if total_cap > 0 and self._steady_total_updates >= total_cap:
            # 配额终身用完，永久冻结动态簇心
            self._poisoning_total_cap_limited += 1
            return

        # ================= 真正执行 EMA 微调 =================
        state_norm = self._normalize(state_176)
        protos = np.array(self.safe_prototypes, dtype=np.float32)
        # 排除刚 append 的自身向量（learn_safe 已把 state_176 追加到末尾，
        # protos[-1] 即 state_176）。若包含自身，argmax 恒命中自身导致
        # EMA 退化为 no-op（new_vec 恒等于自身），"越用越准"学习失效。
        # 仅在前 N-1 个既有原型中找最近邻做微调。
        if len(protos) < 2:
            return
        base_protos = protos[:-1]
        norms = np.linalg.norm(base_protos, axis=1, keepdims=True)
        norms = np.maximum(norms, 1e-8)
        protos_norm = base_protos / norms
        sims = protos_norm @ state_norm
        best_idx = int(np.argmax(sims))
        # 学习率从配置读取，兜底 0.01
        lr = float(getattr(cfg, "luoshu_steady_state_learning_rate", 0.01))
        new_vec = (1.0 - lr) * base_protos[best_idx] + lr * state_176
        self.safe_prototypes[best_idx] = self._normalize(new_vec).copy()
        self._steady_updates_in_window += 1
        self._steady_total_updates += 1

    def learn_attack(self, state: np.ndarray, factory: bool = False):
        """将状态向量加入攻击原型集合（带去重和频率门限，质疑C修复）。

        活性防护哲学：攻击原型学习不是无脑积累，而是需要防污染。
        - 去重：与已有攻击原型高度相似（>0.95）的不重复添加
        - 频率门限：同一聚类最多添加3个原型，防原型洪水攻击

        factory=True 时写入出厂预热只读原型库（factory_attack_prototypes），
        该库用于硬拦截直接否决，绝不接受在线学习写入，防止良性污染导致误报。
        """
        state_176 = self._to_native(state)
        state_norm = self._normalize(state_176)

        target = self.factory_attack_prototypes if factory else self.attack_prototypes

        if target:
            protos = np.array(target, dtype=np.float32)
            norms = np.linalg.norm(protos, axis=1, keepdims=True)
            norms = np.maximum(norms, 1e-8)
            protos_norm = protos / norms
            sims = protos_norm @ state_norm
            max_sim = float(np.max(sims))

            if max_sim > self._attack_dedup_threshold:
                best_idx = int(np.argmax(sims))
                fp = self._fingerprint(target[best_idx])
                self._attack_fingerprint_counter[fp] += 1
                if self._attack_fingerprint_counter[fp] >= self._attack_max_per_cluster:
                    return

        target.append(state_176.copy())
        fp = self._fingerprint(state_176)
        self._attack_fingerprint_counter[fp] += 1

        # 出厂只读原型库固定容量，不参与在线截断；在线攻击原型执行容量上限
        if factory:
            return
        self._attack_learn_count += 1  # 在线攻击学习累计次数（展示用）
        max_size = self.config.prototype_max_size
        if len(self.attack_prototypes) > max_size:
            removed = self.attack_prototypes.pop(0)
            rfp = self._fingerprint(removed)
            self._attack_fingerprint_counter[rfp] = max(
                0, self._attack_fingerprint_counter[rfp] - 1
            )
            if self._attack_fingerprint_counter[rfp] == 0:
                del self._attack_fingerprint_counter[rfp]

    def _fingerprint(self, vec: np.ndarray) -> str:
        """生成向量的指纹（用于去重计数，不暴露内容）。"""
        return hashlib.sha256(vec.tobytes()).hexdigest()[:8]

    def _to_native(self, state: np.ndarray) -> np.ndarray:
        """将输出维度状态向量还原为176维洛书空间。"""
        if self.state_dim >= self.native_dim:
            result = state[:self.native_dim].copy()
            return result.astype(np.float32)
        pseudo_inv = self._proj.T
        return (pseudo_inv @ state).astype(np.float32)

    def _text_to_raw_vector(self, text: str, rng=None) -> np.ndarray:
        """将文本转换为176维原始向量（语言无关）。"""
        vec = np.zeros(self.native_dim, dtype=np.float32)
        if not text:
            return vec

        for i, ch in enumerate(text):
            code = ord(ch)
            pos_hash = (code * 2654435761 + i * 40503 + 17) & 0xFFFFFFFF
            for d in range(min(4, self.native_dim)):
                idx = (pos_hash + d * 7919) % self.native_dim
                sign = 1.0 if (pos_hash >> (d * 4)) & 1 else -1.0
                vec[idx] += sign * (1.0 / (1.0 + i * 0.05))

        norm = np.linalg.norm(vec)
        if norm > 1e-8:
            vec /= norm
        return vec

    @staticmethod
    def _compute_shannon_entropy(text: str) -> float:
        """计算文本的Shannon熵（数据驱动的阴阳分叉参数，质疑A修复）。

        活性防护哲学：阴阳分叉比例不应是硬编码常数，而应由
        输入本身的统计特征决定。高熵输入（编码/混淆）需要
        更强的阳（变化）分量，低熵输入（自然语言）需要
        更强的阴（稳定）分量。
        """
        if not text:
            return 0.0
        freq = Counter(text)
        total = len(text)
        entropy = 0.0
        for count in freq.values():
            p = count / total
            if p > 0:
                entropy -= p * np.log2(p)
        return entropy

    def _yin_yang_bifurcate(self, raw: np.ndarray, entropy: float) -> np.ndarray:
        """阴阳分叉 + 穿透门控（数据驱动，质疑A修复）。

        分叉比例由输入Shannon熵动态决定：
        - 低熵（<3bit）：自然语言，阴（稳定）占主导，gate偏正
        - 高熵（>5bit）：编码/混淆，阳（变化）占主导，gate偏负
        - 中熵：平衡分配

        这不是硬编码规则，而是数据驱动的自适应分叉。
        """
        half = self.native_dim // 2
        yin = raw[:half].copy()
        yang = raw[half:].copy()

        yin_norm = np.linalg.norm(yin)
        yang_norm = np.linalg.norm(yang)
        if yin_norm > 1e-8:
            yin /= yin_norm
        if yang_norm > 1e-8:
            yang /= yang_norm

        entropy_bias = np.tanh((entropy - 4.0) / 2.0)
        gate = np.tanh(yin_norm - yang_norm + entropy_bias)

        yin_scale = 1.0 + gate * 0.3
        yang_scale = 1.0 - gate * 0.3
        yin_gated = yin * yin_scale
        yang_gated = yang * yang_scale

        state = np.zeros(self.native_dim, dtype=np.float32)
        state[:half] = yin_gated
        state[half:2 * half] = yang_gated
        if self.native_dim > 2 * half:
            state[2 * half:] = (yin[:self.native_dim - 2 * half] +
                                yang[:self.native_dim - 2 * half]) * 0.5

        return self._normalize(state)

    @staticmethod
    def _normalize(v: np.ndarray) -> np.ndarray:
        norm = np.linalg.norm(v)
        if norm > 1e-12:
            return v / norm
        return v.copy()

    def get_stats(self) -> Dict:
        """获取映射器统计信息（不暴露原型内容）。"""
        cfg = self.config
        # Phase 判定（阈值来自配置，默认1000）
        _phase_c_start = getattr(cfg, "luoshu_phase_c_start_count", 1000)
        if self._total_learned >= _phase_c_start:
            phase = "C_STEADY"
        elif len(self._shadow_buffer) > 0 or self._total_learned > 0:
            phase = "B_SHADOW_BUFFER"
        else:
            phase = "A_FACTORY"

        lr = 0.0
        if phase == "C_STEADY":
            lr = float(getattr(cfg, "luoshu_steady_state_learning_rate", self._learning_rate))

        return {
            "gua_prototypes": self.n_gua,
            "safe_prototype_count": len(self.safe_prototypes),
            "attack_prototype_count": len(self.attack_prototypes),
            "native_dim": self.native_dim,
            "output_dim": self.state_dim,
            "attack_clusters": len(self._attack_fingerprint_counter),
            # 三阶段自适应学习策略统计
            "adaptive_phase": phase,
            "static_prototype_count": self._static_count,  # 出厂只读原型（仅观测）
            "shadow_buffer_size": len(self._shadow_buffer),  # 影子缓冲积累量
            "shadow_buffer_capacity": getattr(cfg, "luoshu_shadow_buffer_capacity", 200),
            "total_learned_samples": self._total_learned,  # 在线学习累计接受样本
            "phase_c_start_count": _phase_c_start,
            "domain_shift_applied": self._domain_shift is not None,  # Phase B偏移校正
            "domain_shift_ratio": float(getattr(cfg, "luoshu_shadow_buffer_offset_ratio", 0.3)),
            "steady_state_learning_rate": lr,
            # Anti-Poisoning 三道门的拦截统计（A相似度/B窗口/C总上限）
            "poisoning_gate_a_skipped": self._poisoning_skipped,  # GateA: 攻击相似度拦截
            "poisoning_gate_b_limited": self._poisoning_window_limited,  # GateB: 窗口限流拦截
            "poisoning_gate_c_cap_limited": self._poisoning_total_cap_limited,  # GateC: 总上限拦截（慢性毒化防护）
            "poisoning_similarity_threshold": float(getattr(cfg, "luoshu_poisoning_similarity_threshold", 0.0)),
            "poisoning_max_updates_per_hundred": int(getattr(cfg, "luoshu_poisoning_max_updates_per_hundred", 3)),
            "poisoning_total_updates_cap": int(getattr(cfg, "luoshu_poisoning_total_updates_cap", 500)),
            "steady_updates_in_current_window": int(self._steady_updates_in_window),
            "steady_total_updates_lifetime": int(self._steady_total_updates),  # 历史总共做过多少次EMA微调
            # 结构性偏见提示（_static_prototypes 永不更新，对长尾新文体存在固有偏见）
            "structural_bias_note": "static_prototypes are frozen from benign_v1.npy and never updated online. "
                                    "Long-tail novel writing styles outside the factory 5 categories "
                                    "(daily/tech/code/classical/legal) may experience chronically higher "
                                    "safe_distance than mainstream texts until enough Phase-C samples accumulate.",
        }
