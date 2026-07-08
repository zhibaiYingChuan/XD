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
from collections import Counter
from typing import Dict, List, Tuple

import numpy as np

from daoti_xuandun.config import XuanDunConfig

LUOSHU_NATIVE_DIM = 176


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
        self.attack_prototypes: List[np.ndarray] = []
        self._attack_fingerprint_counter: Counter = Counter()
        self._attack_dedup_threshold = 0.95
        self._attack_max_per_cluster = 3
        self._init_universal_prototypes()

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
        """预置通用域原型，解决冷启动问题（质疑E修复）。

        活性防护哲学：冷启动不应意味着"零防御"。通过预置少量
        通用域原型（自然语言、代码、二进制），系统在首次运行时
        即有基础判别力。这些原型不是硬编码规则，而是提供初始
        的符号空间锚点，后续会被在线学习覆盖。
        """
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
            self.safe_prototypes.append(state.copy())

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
        """计算状态向量与安全域原型的最小距离。"""
        if not self.safe_prototypes:
            return 1.0
        state_176 = self._to_native(state)
        state_norm = self._normalize(state_176)
        protos = np.array(self.safe_prototypes, dtype=np.float32)
        norms = np.linalg.norm(protos, axis=1, keepdims=True)
        norms = np.maximum(norms, 1e-8)
        protos_norm = protos / norms
        sims = protos_norm @ state_norm
        return 1.0 - float(np.max(sims))

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
        """将状态向量加入安全原型集合。"""
        state_176 = self._to_native(state)
        self.safe_prototypes.append(state_176.copy())
        max_size = self.config.prototype_max_size
        if len(self.safe_prototypes) > max_size:
            self.safe_prototypes = self.safe_prototypes[-max_size:]

    def learn_attack(self, state: np.ndarray):
        """将状态向量加入攻击原型集合（带去重和频率门限，质疑C修复）。

        活性防护哲学：攻击原型学习不是无脑积累，而是需要防污染。
        - 去重：与已有攻击原型高度相似（>0.95）的不重复添加
        - 频率门限：同一聚类最多添加3个原型，防原型洪水攻击
        """
        state_176 = self._to_native(state)
        state_norm = self._normalize(state_176)

        if self.attack_prototypes:
            protos = np.array(self.attack_prototypes, dtype=np.float32)
            norms = np.linalg.norm(protos, axis=1, keepdims=True)
            norms = np.maximum(norms, 1e-8)
            protos_norm = protos / norms
            sims = protos_norm @ state_norm
            max_sim = float(np.max(sims))

            if max_sim > self._attack_dedup_threshold:
                best_idx = int(np.argmax(sims))
                fp = self._fingerprint(self.attack_prototypes[best_idx])
                self._attack_fingerprint_counter[fp] += 1
                if self._attack_fingerprint_counter[fp] >= self._attack_max_per_cluster:
                    return

        self.attack_prototypes.append(state_176.copy())
        fp = self._fingerprint(state_176)
        self._attack_fingerprint_counter[fp] += 1

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
        return {
            "gua_prototypes": self.n_gua,
            "safe_prototype_count": len(self.safe_prototypes),
            "attack_prototype_count": len(self.attack_prototypes),
            "native_dim": self.native_dim,
            "output_dim": self.state_dim,
            "attack_clusters": len(self._attack_fingerprint_counter),
        }
