# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白
# 本文件受道体研究许可证 v1.0 约束，禁止逆向工程和再分发
# 详见 LICENSE 文件

# 自组织符号映射 — 基于流形拓扑的原型竞争
# 符号边界动态调整，符号表可扩展，攻击者无法建立静态逆映射。

from collections import OrderedDict
from typing import List, Optional

import numpy as np

from daoti_xuandun.config import XuanDunConfig


class SelfOrganizingMapper:
    """自组织符号映射 — 基于原型竞争的动态符号映射。

    核心机制：
    - 每个符号对应一个高维空间中的原型向量
    - 输入被映射到最近的原型（竞争学习），符号边界动态调整
    - 符号表可动态扩展（当现有符号无法区分新输入时）
    - 历史一致性：相同输入哈希返回相同符号序列，确保合法用户稳定

    Attributes:
        config: 全局配置。
        dim: 向量维度。
        table_size: 符号表大小。
        prototypes: 符号原型矩阵，shape (table_size, dim)。
        step_count: 累计调用次数，控制学习率衰减。
        history_cache: 输入哈希 → 符号序列的 LRU 缓存。
    """

    def __init__(self, config: XuanDunConfig):
        self.config = config
        self.dim = config.hidden_dim
        self.table_size = config.symbol_table_size
        self._key = config.mapping_key
        self.step_count: int = 0
        self._init_prototypes()
        self.history_cache: OrderedDict = OrderedDict()
        self._cache_max = config.som_history_cache_size
        self._winner_counts = np.zeros(self.table_size, dtype=np.float32)
        self._total_calls = 0

    def _init_prototypes(self):
        """初始化符号原型为随机单位向量。"""
        rng = np.random.default_rng(seed=int.from_bytes(self._key, "little"))
        self.prototypes = rng.normal(0, 1, (self.table_size, self.dim)).astype(np.float32)
        for i in range(self.table_size):
            self.prototypes[i] = self._normalize(self.prototypes[i])

    def map(self, vec: np.ndarray, cache_key: Optional[int] = None) -> List[int]:
        """将向量映射为符号序列（竞争学习）。

        相同输入哈希优先返回缓存符号，确保合法用户时序稳定。
        新输入通过竞争学习映射并更新原型。

        Args:
            vec: 输入向量，shape (dim,)。
            cache_key: 可选的外部缓存键，用于管线场景中
                       基于原始输入（而非壳输出）做缓存查找。

        Returns:
            符号索引列表。
        """
        vec = np.asarray(vec, dtype=np.float32)
        self.step_count += 1

        lookup_key = cache_key if cache_key is not None else self._hash_vector(vec)
        if lookup_key in self.history_cache:
            self.history_cache.move_to_end(lookup_key)
            return list(self.history_cache[lookup_key])

        syms = self._competitive_map(vec)

        self._add_to_cache(lookup_key, syms)

        return syms

    def _competitive_map(self, vec: np.ndarray) -> List[int]:
        """竞争学习映射：每个维度独立竞争最近原型。"""
        vec_norm = self._normalize(vec)
        diffs = vec_norm.reshape(1, -1) - self.prototypes
        dists = diffs * diffs
        winners = np.argmin(dists, axis=0)
        self._adjust_prototypes(vec_norm, winners)
        return [int(w) for w in winners]

    def _hash_vector(self, vec: np.ndarray) -> int:
        """对向量生成稳定哈希，用于历史缓存查找。"""
        safe_vec = np.nan_to_num(vec, nan=0.0, posinf=1e6, neginf=-1e6)
        quantized = (np.clip(safe_vec, -1e6, 1e6) * 1000).astype(np.int64)
        h = 0
        for i, v in enumerate(quantized.flat):
            h ^= int(v) * (2654435761 + i * 31)
        return h & 0x7FFFFFFF

    def _add_to_cache(self, input_hash: int, syms: List[int]):
        """将映射结果加入 LRU 缓存，超限时淘汰最旧条目。"""
        if len(self.history_cache) >= self._cache_max:
            self.history_cache.popitem(last=False)
        self.history_cache[input_hash] = tuple(syms)

    def _adjust_prototypes(self, vec: np.ndarray, winners: np.ndarray):
        """竞争学习：优胜原型向对应维度的输入值移动。

        频繁胜出的原型学习率衰减（锁定），防止被攻击者拖动。
        罕见胜出的原型保持高学习率（塑性），维持对新模式的适应力。
        """
        self._total_calls += 1
        unique_winners = set(int(w) for w in winners)
        for w in unique_winners:
            self._winner_counts[w] += 1

        base_lr = self.config.som_learning_rate * (1.0 / (1.0 + self.step_count * 0.001))
        for w in unique_winners:
            freq = self._winner_counts[w] / max(1, self._total_calls)
            annealing = 1.0 / (1.0 + self._total_calls * 0.0001)
            lock_factor = 1.0 / (1.0 + freq * 3.0 * annealing)
            lr = base_lr * lock_factor
            mask = winners == w
            self.prototypes[w][mask] = (1 - lr) * self.prototypes[w][mask] + lr * vec[mask]
            self.prototypes[w] = self._normalize(self.prototypes[w])

    @staticmethod
    def _normalize(v: np.ndarray) -> np.ndarray:
        norm = np.linalg.norm(v)
        if norm > 1e-12:
            return v / norm
        return v.copy()

    def expand_table(self, new_size: int):
        """动态扩展符号表，新增原型从现有原型变异生成。"""
        if new_size <= self.table_size:
            return

        rng = np.random.default_rng(seed=self.step_count + 1)
        new_protos = np.zeros((new_size, self.dim), dtype=np.float32)
        new_protos[: self.table_size] = self.prototypes

        for i in range(self.table_size, new_size):
            parent_idx = rng.integers(0, self.table_size)
            new_protos[i] = self.prototypes[parent_idx] + rng.normal(0, 0.1, self.dim).astype(np.float32)
            new_protos[i] = self._normalize(new_protos[i])

        self.prototypes = new_protos
        self.table_size = new_size

    def inverse_map(self, symbols: List[int]) -> Optional[np.ndarray]:
        """从符号恢复近似向量（取原型向量）。"""
        recovered = np.zeros((len(symbols), self.dim), dtype=np.float32)
        for i, s in enumerate(symbols):
            if 0 <= s < self.table_size:
                recovered[i] = self.prototypes[s]
        return recovered

    @property
    def current_table_size(self) -> int:
        return self.table_size