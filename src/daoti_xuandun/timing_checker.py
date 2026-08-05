from __future__ import annotations
# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白
# 本文件受道体研究许可证 v1.0 约束，禁止逆向工程和再分发
# 详见 LICENSE 文件

# Implements §6 模块四：时序一致性校验

import time
from collections import deque
from typing import Any, Dict, List, Optional, Set, Tuple


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

        # ── 多轮对话状态跟踪：会话级 trust_decay + intent_drift ──
        #   _session_trust         : 下一轮 check() 要暴露的 trust（衰减后存储，为下轮准备）
        #   _session_exposed_trust : 本轮 check() 对外暴露的 trust（get_session_state 读取）
        #   turn_count             : 累计轮数，用于 min_turns 冷启动豁免
        #   intent_drift_score     : 基于 domain_distance EWMA 的 σ 偏离倍数（每轮 XuanDun.update_drift_with_domain_distance 注入）
        #
        #   设计决策：intent_drift 基于内生域距离（domain_distance）而非时序距离（timing）
        #     - 时序距离需要滑动窗口（默认≥32）填满后才有稳定协方差，导致 8 轮短会话无法计算
        #     - 内生域距离每轮都有产出，EWMA 只需 6 轮即可获得稳定的均值/方差
        self._session_trust: Dict[str, float] = {}
        self._session_exposed_trust: Dict[str, float] = {}
        self._session_turn_count: Dict[str, int] = {}
        self._session_last_drift_score: Dict[str, float] = {}
        self._session_last_drift_detected: Dict[str, bool] = {}
        # domain_distance 的 EWMA 均值/方差（独立于 timing 的 EWMA）
        self._domain_ewma_mean: Dict[str, float] = {}
        self._domain_ewma_var: Dict[str, float] = {}
        # 平滑系数与 drift 配置（复用 timing EWMA 系数，保持一致）
        self._domain_ewma_alpha: float = 0.1
        self._trust_decay_rate = getattr(config, 'session_trust_decay_rate', 0.95)
        self._trust_floor = getattr(config, 'session_trust_floor', 0.30)
        self._drift_sigma = getattr(config, 'session_intent_drift_sigma', 2.5)
        self._drift_min_turns = getattr(config, 'session_intent_drift_min_turns', 6)

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

    def _ensure_session_state(self, session_id: str) -> None:
        """确保某个会话的多轮状态字典已初始化。"""
        if session_id not in self._session_trust:
            # 首轮对外暴露 1.0，衰减存为下一轮的值
            self._session_trust[session_id] = 1.0
            self._session_exposed_trust[session_id] = 1.0
            self._session_turn_count[session_id] = 0
            self._session_last_drift_score[session_id] = 0.0
            self._session_last_drift_detected[session_id] = False

    def advance_turn(self, session_id: str) -> None:
        """§6.2.0 在本轮 protect() 早期推进会话状态（turn_count++ + trust_decay 衰减）。

        调用时机：XuanDun._protect_impl 阶段1（内生域感知）结束后立刻调用，
        保证即便后续分支（如 domain_awareness REJECT）提前 return，
        本轮的 turn_count 与 trust_decay 也已正确前进到"本轮"。

        行为（幂等：同一 session_id 同一轮多次调用不重复前进）：
          - 若 _session_trust 未初始化：初始化 trust=1.0, turn=0
          - turn_count += 1（首次进入时从 0 → 1）
          - 暴露 trust_current = _session_trust[sid]（首轮 = 1.0）
          - 计算下一轮 trust_next = max(floor, trust_current × decay_rate)
          - 写回 _session_trust[sid] = trust_next（为下一轮准备）
        """
        self._ensure_session_state(session_id)
        # 记录 session 访问时间（用于 LRU / TTL 淘汰）
        self._session_access[session_id] = time.monotonic()
        # 推进 turn_count
        self._session_turn_count[session_id] += 1
        # ── trust_decay：先暴露当前值，再衰减存为下一轮 ──
        trust_current = float(self._session_trust[session_id])
        trust_next = max(self._trust_floor, trust_current * self._trust_decay_rate)
        self._session_exposed_trust[session_id] = trust_current
        self._session_trust[session_id] = trust_next

    # Implements §6.2 check
    def check(self, sym_seq: SymbolSeq, session_id: str) -> Tuple[TimingDecision, float]:
        """§6.2 检查时序一致性 + 会话级 trust_decay + intent_drift。

        注意：advance_turn() 已在 XuanDun 阶段1 提前调用过，负责 turn_count++/trust_decay；
        check() 内不再重复推进多轮状态，避免 double-decay。

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

        self._ensure_session_state(session_id)
        # 更新 session 访问时间（用于 LRU / TTL 淘汰）
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

    def update_drift_with_domain_distance(
        self, session_id: str, domain_distance: Optional[float]
    ) -> None:
        """§6.2.1 基于内生域距离（domain_distance）的意图漂移 EWMA 跟踪。

        XuanDun 在每轮 _protect_impl 的阶段 1（内生域感知）结束后调用本方法，
        把当前轮的 domain_distance 注入时序校验器，用于计算 intent_drift。

        计算逻辑：
          1. 若 domain_distance 为 None，跳过（不更新 EWMA）
          2. 若会话尚未初始化 turn_count（= 0），跳过（首轮到 check() 再初始化）
          3. 首 6 轮：纯累积 EWMA 均值/方差，不计算漂移（cold_start 豁免）
          4. 第 min_turns+1 轮起：计算 |d - ewma_mean| / sqrt(ewma_var) = drift_score
          5. drift_score > drift_sigma 时，intent_drift_detected = True

        Args:
            session_id: 会话标识符。
            domain_distance: 内生域感知返回的域距离（最近原型距离）。
        """
        if domain_distance is None:
            return

        d = float(domain_distance)
        alpha = self._domain_ewma_alpha

        if session_id not in self._domain_ewma_mean:
            # 初始化：首轮用当前值起步，方差设为极小值避免 sigma=0
            self._domain_ewma_mean[session_id] = d
            self._domain_ewma_var[session_id] = 1e-4
            return

        # 更新 EWMA 均值/方差
        prev_m = self._domain_ewma_mean[session_id]
        prev_v = self._domain_ewma_var[session_id]
        new_m = alpha * d + (1 - alpha) * prev_m
        new_v = alpha * (d - prev_m) ** 2 + (1 - alpha) * prev_v
        self._domain_ewma_mean[session_id] = new_m
        self._domain_ewma_var[session_id] = max(1e-8, new_v)

        turn_count = int(self._session_turn_count.get(session_id, 0))
        sigma = float(np.sqrt(max(1e-8, new_v)))
        drift_score = abs(d - new_m) / sigma
        self._session_last_drift_score[session_id] = drift_score
        self._session_last_drift_detected[session_id] = bool(
            turn_count >= self._drift_min_turns and drift_score > self._drift_sigma
        )

    def get_session_state(self, session_id: str) -> dict:
        """返回指定会话的 trust_decay + intent_drift 状态。

        用于 XuanDun._protect_impl 将状态透传到 ProtectResult 与 /protect API。
        若会话不存在（未调用过check），返回默认的初始值。

        Returns:
            {
                "trust_decay_value": float,       # 衰减后的信任度 [trust_floor, 1.0]
                "intent_drift_score": float,     # σ 偏离倍数
                "intent_drift_detected": bool,   # 是否超过漂移阈值
                "turn_count": int,               # 累计轮数
            }
        """
        if session_id not in self._session_trust:
            return {
                "trust_decay_value": 1.0,
                "intent_drift_score": 0.0,
                "intent_drift_detected": False,
                "turn_count": 0,
            }
        # 优先读取本轮已暴露的 trust（check() 中写入），否则回退到下一轮缓存
        exposed = self._session_exposed_trust.get(session_id, self._session_trust[session_id])
        return {
            "trust_decay_value": float(exposed),
            "intent_drift_score": float(self._session_last_drift_score.get(session_id, 0.0)),
            "intent_drift_detected": bool(self._session_last_drift_detected.get(session_id, False)),
            "turn_count": int(self._session_turn_count.get(session_id, 0)),
        }

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
        # 同步清理多轮会话状态
        self._session_trust.pop(lru_session, None)
        self._session_exposed_trust.pop(lru_session, None)
        self._session_turn_count.pop(lru_session, None)
        self._session_last_drift_score.pop(lru_session, None)
        self._session_last_drift_detected.pop(lru_session, None)
        self._domain_ewma_mean.pop(lru_session, None)
        self._domain_ewma_var.pop(lru_session, None)

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
            # 同步清理多轮会话状态
            self._session_trust.pop(sid, None)
            self._session_exposed_trust.pop(sid, None)
            self._session_turn_count.pop(sid, None)
            self._session_last_drift_score.pop(sid, None)
            self._session_last_drift_detected.pop(sid, None)
            self._domain_ewma_mean.pop(sid, None)
            self._domain_ewma_var.pop(sid, None)

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
