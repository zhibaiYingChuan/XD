# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白
# 本文件受道体研究许可证 v1.0 约束，禁止逆向工程和再分发
# 详见 LICENSE 文件

# Implements §6 模块四：时序一致性校验

import time
from collections import deque
from typing import Dict, Tuple

import numpy as np

from daoti_xuandun.config import XuanDunConfig
from daoti_xuandun.types import SymbolSeq, TimingDecision


class TimingConsistencyChecker:
    """§6.2 时序一致性校验 - 检测重放及节律异常。

    抗漂移机制：使用 EWMA + 异常剔除动态调整阈值，
    防止攻击者通过 low-and-slow 攻击驯化协方差矩阵。

    Attributes:
        config: 全局配置。
        window_size: 滑动窗口长度。
        threshold: 基础马氏距离阈值。
        table_size: 符号表大小（用于直方图维度）。
        state: session_id -> deque of feature vectors。
        ewma_mean: session_id -> EWMA 均值。
        ewma_var: session_id -> EWMA 方差。
        distance_history: session_id -> 最近距离历史。
    """

    def __init__(self, config: XuanDunConfig):
        """
        Args:
            config: 全局配置对象。
        """
        self.config = config
        self.window_size = config.max_window_size
        self.threshold = config.anomaly_threshold
        self.table_size = config.symbol_table_size
        self.state: Dict[str, deque] = {}
        self.ewma_mean: Dict[str, float] = {}
        self.ewma_var: Dict[str, float] = {}
        self.distance_history: Dict[str, deque] = {}
        self.ewma_alpha = getattr(config, 'timing_ewma_alpha', 0.1)
        self.threshold_floor = getattr(config, 'timing_threshold_floor', 0.5)
        self.max_sessions = getattr(config, 'max_sessions', 10000)
        self.session_ttl = getattr(config, 'session_ttl', 7200)
        self._session_access: Dict[str, float] = {}
        self._last_expire_check: float = 0.0

    # Implements §6.2 _extract_feature
    def _extract_feature(self, sym_seq: SymbolSeq) -> np.ndarray:
        """§6.2 提取归一化直方图特征。

        Args:
            sym_seq: 符号序列。

        Returns:
            归一化直方图，shape (table_size,)。
        """
        hist = np.zeros(self.table_size, dtype=np.float64)
        for s in sym_seq:
            if 0 <= s < self.table_size:
                hist[s] += 1
        total = len(sym_seq)
        if total > 0:
            hist = hist / total
        return hist

    # Implements §6.2 check
    def check(self, sym_seq: SymbolSeq, session_id: str) -> Tuple[TimingDecision, float]:
        """§6.2 检查时序一致性。

        处理流程：
        1. 提取特征向量（归一化直方图）
        2. 若窗口未满，加入并返回 PASS
        3. 若已满，计算马氏距离
        4. 超过阈值 → 告警

        Args:
            sym_seq: 符号序列。
            session_id: 会话标识符。

        Returns:
            (decision, distance) 二元组。
        """
        feat = self._extract_feature(sym_seq)

        self._expire_sessions()

        if session_id not in self.state:
            self.state[session_id] = deque(maxlen=self.window_size)
            self._evict_lru()

        self._session_access[session_id] = time.monotonic()

        window = self.state[session_id]

        if len(window) < self.window_size:
            window.append(feat)
            return TimingDecision.PASS, 0.0

        # 窗口已满，计算马氏距离
        features = np.array(list(window), dtype=np.float64)
        mean = np.mean(features, axis=0)
        cov = np.cov(features, rowvar=False)
        cov_inv = np.linalg.pinv(cov + np.eye(self.table_size) * 1e-6)

        distance = self._mahalanobis(feat, mean, cov_inv)

        # 窗口异常剔除：仅当特征不是异常值时才加入窗口
        # 防止攻击者通过 low-and-slow 方式污染窗口统计
        is_outlier = self._is_window_outlier(feat, features, mean, cov_inv)
        if not is_outlier:
            window.append(feat)

        adaptive_threshold = self._adaptive_threshold(session_id, distance)

        if distance > adaptive_threshold:
            return TimingDecision.REJECT, distance

        return TimingDecision.PASS, distance

    def _adaptive_threshold(self, session_id: str, distance: float) -> float:
        """抗漂移自适应阈值：EWMA + 异常剔除 + 硬下限。

        与内生域感知的阈值算法一致，防止 low-and-slow 攻击驯化
        时序校验的协方差统计。

        Args:
            session_id: 会话标识符。
            distance: 当前马氏距离。

        Returns:
            自适应阈值。
        """
        if session_id not in self.distance_history:
            self.distance_history[session_id] = deque(maxlen=64)

        hist = self.distance_history[session_id]
        hist.append(distance)

        if len(hist) < 8:
            return self.threshold

        recent = list(hist)
        alpha = self.ewma_alpha

        if session_id not in self.ewma_mean:
            self.ewma_mean[session_id] = float(np.median(recent))
            self.ewma_var[session_id] = float(np.var(recent) + 1e-8)

        for d in recent[-4:]:
            dev = abs(float(d) - self.ewma_mean[session_id]) / (np.sqrt(self.ewma_var[session_id]) + 1e-8)
            if dev < 2.0:
                self.ewma_mean[session_id] = alpha * float(d) + (1 - alpha) * self.ewma_mean[session_id]
                self.ewma_var[session_id] = alpha * (float(d) - self.ewma_mean[session_id]) ** 2 + (1 - alpha) * self.ewma_var[session_id]

        dynamic = self.ewma_mean[session_id] * 2.5
        return float(max(self.threshold_floor, min(dynamic, self.threshold * 3.0)))

    def _is_window_outlier(self, feat: np.ndarray, features: np.ndarray,
                           mean: np.ndarray, cov_inv: np.ndarray) -> bool:
        """判断特征向量是否为窗口内的异常值。

        使用马氏距离检查新特征与窗口分布的距离。
        若距离显著偏离（> 2σ），视为异常，不加入窗口。
        """
        dist = self._mahalanobis(feat, mean, cov_inv)
        if len(features) >= 4:
            all_dists = np.array([self._mahalanobis(f, mean, cov_inv) for f in features])
            median_dist = np.median(all_dists)
            mad = np.median(np.abs(all_dists - median_dist)) * 1.4826
            if mad > 1e-8:
                return dist > median_dist + 3.0 * mad
        return dist > self.threshold * 2.0

    def _evict_lru(self):
        """LRU 淘汰：会话数超限时，移除最久未访问的会话。"""
        if len(self.state) <= self.max_sessions:
            return
        lru_session = min(self._session_access, key=self._session_access.get)
        self.state.pop(lru_session, None)
        self.ewma_mean.pop(lru_session, None)
        self.ewma_var.pop(lru_session, None)
        self.distance_history.pop(lru_session, None)
        self._session_access.pop(lru_session, None)

    def _expire_sessions(self):
        now = time.monotonic()
        if now - self._last_expire_check < 60.0:
            return
        self._last_expire_check = now
        expired = [sid for sid, last in self._session_access.items()
                   if now - last > self.session_ttl]
        for sid in expired:
            self.state.pop(sid, None)
            self.ewma_mean.pop(sid, None)
            self.ewma_var.pop(sid, None)
            self.distance_history.pop(sid, None)
            self._session_access.pop(sid, None)

    # Implements §6.3 马氏距离
    @staticmethod
    def _mahalanobis(x: np.ndarray, mean: np.ndarray, cov_inv: np.ndarray) -> float:
        """§6.3 计算马氏距离。

        d = sqrt((x - mean)^T @ cov_inv @ (x - mean))

        Args:
            x: 当前特征向量。
            mean: 历史均值向量。
            cov_inv: 协方差矩阵的逆（或伪逆）。

        Returns:
            马氏距离值。
        """
        delta = x - mean
        quad = float(delta.T @ cov_inv @ delta)
        return float(np.sqrt(max(0.0, quad)))
