# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白
# 本文件受道体研究许可证 v1.0 约束，禁止逆向工程和再分发
# 详见 LICENSE 文件

from collections import deque
from typing import Optional, Tuple, Union
import hashlib
import math
import re
import time

import numpy as np

from daoti_xuandun.config import XuanDunConfig
from daoti_xuandun.preprocessors import try_decode_payloads, normalize_unicode, check_imperative_whitelist, contains_attack_keywords, contains_strong_attack_keywords, detect_roleplay_pattern, detect_social_engineering, detect_data_exfiltration, detect_system_prompt_leak, detect_excessive_agency, detect_dangerous_command_pattern, detect_training_data_exploitation, detect_leet_speak_attack
from daoti_xuandun.luoshu_mapper import LuoshuSymbolMapper
from daoti_xuandun.types import Decision, TrustLevel, Vector


def _derive_seed(key: bytes, salt: int) -> int:
    return int.from_bytes(key, "little") ^ (salt * 2654435761)


class EndogenousDomainAwareness:
    """内生域感知 — 在线原型距离比较，自主识别未知域。

    三阶段决策模型：
    - 域内（HIGH/MEDIUM）：距离近，直接通过
    - 域外良性（LOW）：距离远但结构正常，进入混沌期孵化
    - 攻击（REJECT）：距离远且结构异常，或距离极远

    双信号融合决策：
    1. 原型距离（域熟悉度）：输入与已知安全域的余弦距离
    2. 结构异常（可疑度）：字节流/字符分布的统计偏差

    活性防护特性：
    - 重复输入自动降低距离（重复缓存机制）
    - 模式遗忘基于单调时钟+老化分数（频率×新鲜度）
    - 5维攻击否定信号 → EWMA动态权重学习
    - 冷启动自动预热 + 自定义预热样本
    """

    def __init__(self, config: XuanDunConfig):
        self.config = config
        self.dim = config.hidden_dim
        self.prototypes: np.ndarray = np.empty((0, self.dim), dtype=np.float32)
        self.call_count: int = 0
        self.prototype_hit_counts: np.ndarray = np.array([], dtype=np.int32)
        self.chaos_nursery: deque = deque(maxlen=config.chaos_nursery_size)
        self.distance_history: deque = deque(maxlen=128)
        self._accepted_distances: deque = deque(maxlen=128)
        self._key = config.shell_key
        self._ewma_mean: Optional[float] = None
        self._ewma_var: Optional[float] = None
        self._proj_matrix: Optional[np.ndarray] = self._init_projection()
        self._proj_protos_cache: Optional[np.ndarray] = None
        self._proj_protos_version: int = -1
        self._domain_char_profile: dict = {}
        self._domain_char_count: int = 0
        self._domain_byte_profile: Optional[np.ndarray] = None
        self._domain_byte_count: int = 0
        self._domain_trigram_profile: dict = {}
        self._domain_trigram_count: int = 0
        self._domain_char_fourgram_profile: dict = {}
        self._domain_fourgram_count: int = 0
        self._domain_inquiry_prefixes: dict = {}
        self._rejected_fourgram_profile: dict = {}
        self._rejected_fourgram_count: int = 0
        self._repetition_cache: dict = {}
        self._domain_imperative_prefixes: dict = {}
        self._domain_learning_phrases: dict = {}
        self._pattern_timestamps: dict = {}
        self._last_forget_time: float = time.monotonic()
        self._forget_interval_seconds: float = 3600.0
        self._negation_weights: dict = {
            'overlap': 1.0, 'entropy': 1.0,
            'ctrl': 1.0, 'long': 1.0, 'short': 1.0,
        }
        self._negation_feedback: dict = {}
        self._negation_sample_count: int = 0
        self._negation_signal_history: dict = {
            'overlap': [], 'entropy': [], 'ctrl': [], 'long': [], 'short': [],
        }
        self._negation_calibrated: bool = False
        self._negation_weights_locked: bool = False
        self._last_debug_info: Optional[dict] = None
        self._luoshu: Optional[LuoshuSymbolMapper] = None
        self._language_feature_weight: float = 1.0
        self._language_weight_update_counter: int = 0
        self._last_binary_anomaly: float = 0.0
        self._rng = np.random.default_rng(seed=int.from_bytes(self._key, "little") ^ 0x5BD1E995)
        if config.enable_luoshu_mapper:
            self._luoshu = LuoshuSymbolMapper(config)

    def process(
        self, raw_input: Union[str, Vector], session_id: str = ""
    ) -> Tuple[Decision, Optional[Vector], TrustLevel, float]:
        """三阶段决策主入口。

        同一输入在短时间内反复出现，表明它是合法的常规请求，
        重复缓存机制会自动降低其距离。

        Returns:
            (decision, feature_vector, trust_level, distance)
        """
        feat = self._input_to_vector(raw_input)
        self.call_count += 1

        debug_info = None
        if self.config.debug:
            debug_info = {
                "domain_familiarity": None,
                "anomaly_signals": [],
                "decision_reason": None,
            }

        dist, proto_idx = self._nearest_prototype(feat)

        self.distance_history.append(dist)

        domain_threshold = self._compute_threshold()
        reject_boundary = self._compute_reject_boundary()

        structural_anomaly = 0.0
        binary_anomaly = 0.0
        novel_trigram_ratio = 0.0
        is_inquiry = False
        is_learning = False
        luoshu_attack_dist = 1.0
        luoshu_safe_dist = 1.0
        decoded_attack_signal = 0.0
        normalized_benign_signal = False
        imperative_whitelist_signal = 0.0
        keyword_attack_signal = 0.0
        strong_keyword_attack_signal = 0.0
        roleplay_signal = 0.0
        social_engineering_signal = 0.0
        data_exfiltration_signal = 0.0
        system_prompt_leak_signal = 0.0
        excessive_agency_signal = 0.0
        dangerous_command_signal = 0.0
        training_data_exploitation_signal = 0.0
        leet_speak_attack_signal = 0.0
        if isinstance(raw_input, str):
            effective_input = raw_input

            if self.config.enable_imperative_whitelist:
                is_benign, confidence = check_imperative_whitelist(raw_input)
                if is_benign:
                    imperative_whitelist_signal = confidence

            if self.config.enable_unicode_normalize:
                normalized = normalize_unicode(raw_input)
                if normalized != raw_input:
                    norm_feat = self._input_to_vector(normalized)
                    norm_dist, _ = self._nearest_prototype(norm_feat)
                    norm_threshold = self._compute_threshold()
                    if norm_dist < norm_threshold:
                        normalized_benign_signal = True

            if self.config.enable_decode_preprocess:
                payloads = try_decode_payloads(raw_input)
                for payload in payloads:
                    if payload != raw_input:
                        if contains_attack_keywords(payload):
                            decoded_attack_signal = 1.0
                            break
                        p_feat = self._input_to_vector(payload)
                        p_dist, _ = self._nearest_prototype(p_feat)
                        p_reject_boundary = self._compute_reject_boundary()
                        if p_dist > p_reject_boundary:
                            decoded_attack_signal = 1.0
                            break

            is_inquiry = self._is_inquiry_pattern(effective_input)
            is_learning = self._is_learning_context(effective_input)
            if contains_attack_keywords(raw_input) and not is_inquiry and not is_learning:
                keyword_attack_signal = 1.0
            # A2 修复：强攻击关键词信号（无视距离条件直接拦截）
            # 仅在非查询/非学习上下文下触发，避免误拦"什么是越狱"等良性查询
            if contains_strong_attack_keywords(raw_input) and not is_inquiry and not is_learning:
                strong_keyword_attack_signal = 1.0
            # B1 修复：角色扮演越狱检测（组合模式：触发词 + 攻击性指示词）
            # 组合模式本身足够精准（"假装"+"邪恶"才触发），无需 is_inquiry 豁免
            # 否则攻击者只需在 "想象我们在模拟世界中...如何入侵银行？" 末尾加"?"即可绕过
            if detect_roleplay_pattern(raw_input):
                roleplay_signal = 1.0
            # B2 修复：社会工程攻击检测（组合模式：触发词 + 攻击性指示词）
            if detect_social_engineering(raw_input):
                social_engineering_signal = 1.0
            # B3 修复：数据泄露攻击检测（组合模式：敏感数据 + 动作指示词）
            if detect_data_exfiltration(raw_input):
                data_exfiltration_signal = 1.0
            # B4 修复：系统提示词泄露攻击检测（组合模式：系统提示词 + 动作指示词）
            if detect_system_prompt_leak(raw_input):
                system_prompt_leak_signal = 1.0
            # B5 修复：过度代理攻击检测（组合模式：自动执行 + 高风险动作）
            if detect_excessive_agency(raw_input):
                excessive_agency_signal = 1.0
            # B6 修复：危险命令模式检测（直接匹配 rm -rf /、DROP TABLE 等）
            if detect_dangerous_command_pattern(raw_input):
                dangerous_command_signal = 1.0
            # B7 修复：训练数据利用 + 危险主题组合检测
            if detect_training_data_exploitation(raw_input):
                training_data_exploitation_signal = 1.0
            # B8 修复：Leet speak 编码攻击检测（解码后检测攻击关键词）
            if detect_leet_speak_attack(raw_input):
                leet_speak_attack_signal = 1.0
            novel_trigram_ratio = self._compute_novel_trigram_ratio(raw_input)
            self._compute_rare_fourgram_ratio(raw_input)
            fourgram_signal = self._compute_fourgram_signal(raw_input, is_inquiry, is_learning)
            structural_anomaly = self._compute_structural_anomaly(raw_input, is_inquiry, fourgram_signal, dist)
            binary_anomaly = self._compute_binary_anomaly(raw_input)
            self._last_binary_anomaly = binary_anomaly
            leet_signal = self._compute_leet_speak_signal(raw_input)
            homoglyph_signal = self._compute_homoglyph_signal(raw_input)
            luoshu_signal = self._compute_luoshu_signal(raw_input)
            if self._luoshu is not None:
                luoshu_state = self._luoshu.encode(raw_input)
                luoshu_attack_dist = self._luoshu.compute_attack_distance(luoshu_state)
                luoshu_safe_dist = self._luoshu.compute_safe_distance(luoshu_state)
        else:
            fourgram_signal = 0.0
            leet_signal = 0.0
            homoglyph_signal = 0.0
            luoshu_signal = 0.0

        self._language_weight_update_counter += 1
        if self._language_weight_update_counter % 50 == 1:
            self._compute_language_feature_weight()
        global_lang_weight = self._language_feature_weight

        luoshu_lang_weight = self._compute_luoshu_confidence_weight(
            luoshu_attack_dist, luoshu_safe_dist
        )
        lang_weight = min(global_lang_weight, luoshu_lang_weight)
        raw_structural_anomaly = structural_anomaly
        structural_anomaly *= lang_weight

        if novel_trigram_ratio > 0.5:
            base_binary_weight = max(0.15, 0.6 * (1.0 - novel_trigram_ratio * 0.5))
            if fourgram_signal > 0.15:
                binary_weight = 0.6
            elif binary_anomaly >= 0.5:
                binary_weight = max(0.7, base_binary_weight)
            elif is_learning and fourgram_signal < -0.1:
                binary_weight = max(0.05, base_binary_weight * 0.2)
            elif is_learning and fourgram_signal < -0.05:
                binary_weight = max(0.08, base_binary_weight * 0.35)
            elif is_inquiry and fourgram_signal < -0.1:
                binary_weight = max(0.15, base_binary_weight * 0.5)
            elif is_inquiry and fourgram_signal < -0.05:
                binary_weight = max(0.20, base_binary_weight * 0.7)
            elif fourgram_signal < -0.1:
                binary_weight = max(0.05, base_binary_weight * 0.2)
            elif fourgram_signal < -0.05:
                binary_weight = max(0.08, base_binary_weight * 0.35)
            elif abs(fourgram_signal) < 0.05:
                binary_weight = max(0.05, base_binary_weight * 0.5)
            else:
                binary_weight = base_binary_weight
        else:
            if binary_anomaly >= 0.5:
                binary_weight = 0.7
            elif fourgram_signal < -0.1:
                if is_learning:
                    binary_weight = 0.10
                elif is_inquiry:
                    binary_weight = 0.20
                else:
                    binary_weight = 0.15
            elif fourgram_signal < -0.05:
                if is_learning:
                    binary_weight = 0.20
                elif is_inquiry:
                    binary_weight = 0.35
                else:
                    binary_weight = 0.30
            else:
                binary_weight = 0.6
        base_anomaly = max(structural_anomaly, binary_anomaly * binary_weight)
        obfuscation_signal = max(leet_signal, homoglyph_signal)
        if obfuscation_signal > 0:
            base_anomaly = max(base_anomaly, base_anomaly * 0.6 + obfuscation_signal * 0.4)
            if obfuscation_signal > 0.3 and base_anomaly < obfuscation_signal:
                base_anomaly = max(base_anomaly, obfuscation_signal * 0.8)
        if fourgram_signal >= 0:
            fused_anomaly = base_anomaly + fourgram_signal
        elif obfuscation_signal > 0.3:
            max_negative = base_anomaly * 0.6
            fused_anomaly = base_anomaly + max(fourgram_signal, -max_negative)
        elif structural_anomaly > 0.5:
            max_negative = structural_anomaly * 0.4
            fused_anomaly = base_anomaly + max(fourgram_signal, -max_negative)
        else:
            fused_anomaly = base_anomaly + fourgram_signal
        fused_anomaly = max(0.0, fused_anomaly)

        if imperative_whitelist_signal > 0:
            reduction = imperative_whitelist_signal * 0.3
            fused_anomaly = max(0.0, fused_anomaly - reduction)

        if luoshu_signal > 0.2:
            fused_anomaly = max(fused_anomaly, fused_anomaly * 0.6 + luoshu_signal * 0.4)
        elif luoshu_signal > 0:
            fused_anomaly = max(fused_anomaly, fused_anomaly * 0.8 + luoshu_signal * 0.2)
        elif luoshu_signal < -0.2:
            if obfuscation_signal > 0.3:
                fused_anomaly = max(0.0, fused_anomaly * 0.95 + luoshu_signal * 0.05)
            else:
                fused_anomaly = max(0.0, fused_anomaly * 0.85 + luoshu_signal * 0.15)
        elif luoshu_signal < -0.1:
            if obfuscation_signal > 0.3:
                fused_anomaly = max(0.0, fused_anomaly * 0.97 + luoshu_signal * 0.03)
            else:
                fused_anomaly = max(0.0, fused_anomaly * 0.9 + luoshu_signal * 0.1)

        self._luoshu_veto = False
        if self._luoshu is not None and self._luoshu.attack_prototypes:
            if luoshu_attack_dist < 0.15 and luoshu_safe_dist > 0.5:
                self._luoshu_veto = True

        input_key = None
        if isinstance(raw_input, str) and len(raw_input) > 0:
            input_key = int(hashlib.md5(raw_input.encode('utf-8')).hexdigest()[:8], 16) & 0xFFFF
        if input_key is not None:
            if input_key in self._repetition_cache:
                count, _ = self._repetition_cache[input_key]
                self._repetition_cache[input_key] = (count + 1, dist)
                if count >= 3 and raw_structural_anomaly < 0.2:
                    repetition_boost = min(0.3, count * 0.05)
                    dist = max(0.0, dist - repetition_boost)
            else:
                self._repetition_cache[input_key] = (1, dist)
            if len(self._repetition_cache) > 1000:
                keys = list(self._repetition_cache.keys())
                for k in keys[:500]:
                    del self._repetition_cache[k]

        if dist <= domain_threshold * 0.6:
            trust = TrustLevel.HIGH
            decision = Decision.PASS
        elif dist <= domain_threshold * 1.8:
            cold_start_factor = 0.85 if len(self._accepted_distances) < 10 else 1.0
            medium_anomaly_threshold = self.config.structural_anomaly_threshold * 0.8 * cold_start_factor
            if binary_anomaly >= 0.5 and not is_inquiry and not is_learning:
                medium_anomaly_threshold *= 0.25
            if novel_trigram_ratio > 0.5:
                if is_inquiry or is_learning:
                    medium_anomaly_threshold += 0.10
                else:
                    medium_anomaly_threshold += 0.05
            if fourgram_signal < -0.1:
                if binary_anomaly >= 0.5 and not is_inquiry and not is_learning:
                    pass
                elif is_learning:
                    medium_anomaly_threshold += min(0.25, abs(fourgram_signal) * 1.2)
                elif is_inquiry:
                    medium_anomaly_threshold += min(0.20, abs(fourgram_signal) * 1.0)
                else:
                    medium_anomaly_threshold += min(0.15, abs(fourgram_signal) * 0.8)
            elif fourgram_signal < -0.05:
                if not (binary_anomaly >= 0.5 and not is_inquiry and not is_learning):
                    medium_anomaly_threshold += abs(fourgram_signal) * 1.2
            if fused_anomaly > medium_anomaly_threshold:
                reject_threshold = self.config.structural_anomaly_threshold
                if binary_anomaly >= 0.5 and not is_inquiry and not is_learning:
                    reject_threshold *= 0.2
                if fourgram_signal > 0.15:
                    reject_reduction = min(0.10, fourgram_signal * 0.3)
                    reject_threshold -= reject_reduction
                # C1 误报治理：白名单匹配（>0.3）时强制 PASS，攻击信号后置覆盖
                if imperative_whitelist_signal > 0.3 and not (keyword_attack_signal > 0 or strong_keyword_attack_signal > 0):
                    trust = TrustLevel.LOW
                    self.chaos_nursery.append(feat.copy())
                    decision = Decision.PASS
                elif fused_anomaly >= reject_threshold:
                    trust = TrustLevel.UNKNOWN
                    decision = Decision.REJECT
                else:
                    trust = TrustLevel.LOW
                    self.chaos_nursery.append(feat.copy())
                    decision = Decision.PASS
            else:
                trust = TrustLevel.MEDIUM
                decision = Decision.PASS
        elif dist <= reject_boundary:
            cold_start_factor = 0.95 if len(self._accepted_distances) < 10 else 1.0
            dist_range = reject_boundary - domain_threshold * 1.8
            if dist_range > 0:
                dist_ratio = (dist - domain_threshold * 1.8) / dist_range
            else:
                dist_ratio = 1.0
            effective_threshold = self.config.structural_anomaly_threshold * (1.0 - dist_ratio * 0.25) * cold_start_factor
            if novel_trigram_ratio > 0.5:
                if is_inquiry or is_learning:
                    effective_threshold += 0.20
                else:
                    effective_threshold += min(0.10, novel_trigram_ratio * 0.12)
            else:
                effective_threshold += min(0.05, novel_trigram_ratio * 0.08)

            if fourgram_signal < -0.1:
                if is_learning:
                    effective_threshold += min(0.30, abs(fourgram_signal) * 1.2)
                elif is_inquiry:
                    effective_threshold += min(0.25, abs(fourgram_signal) * 1.0)
                else:
                    effective_threshold += min(0.20, abs(fourgram_signal) * 0.8)
            elif fourgram_signal < -0.05:
                effective_threshold += abs(fourgram_signal) * 1.5
            # C1 误报治理：白名单高置信度时提升 effective_threshold
            if imperative_whitelist_signal > 0:
                effective_threshold += imperative_whitelist_signal * 0.4
            # C1 误报治理：白名单匹配（>0.3）时强制 PASS，
            # 攻击信号会在后置检查中覆盖此判定，所以安全
            if imperative_whitelist_signal > 0.3 and not (keyword_attack_signal > 0 or strong_keyword_attack_signal > 0):
                trust = TrustLevel.LOW
                self.chaos_nursery.append(feat.copy())
                decision = Decision.PASS
            elif fused_anomaly < effective_threshold:
                trust = TrustLevel.LOW
                self.chaos_nursery.append(feat.copy())
                decision = Decision.PASS
            else:
                trust = TrustLevel.UNKNOWN
                decision = Decision.REJECT
        else:
            soft_threshold = self.config.structural_anomaly_threshold * 0.6
            if novel_trigram_ratio > 0.5:
                soft_threshold += 0.10
            if fourgram_signal < -0.1:
                if is_learning:
                    soft_threshold += min(0.35, abs(fourgram_signal) * 1.2)
                elif is_inquiry:
                    soft_threshold += min(0.30, abs(fourgram_signal) * 1.0)
                else:
                    soft_threshold += min(0.25, abs(fourgram_signal) * 0.8)
            elif fourgram_signal < -0.05:
                soft_threshold += abs(fourgram_signal) * 1.5
            # C1 误报治理：白名单高置信度时大幅提升 soft_threshold，
            # 让"如何保护API密钥安全"等良性查询即使距离远也能通过
            if imperative_whitelist_signal > 0:
                soft_threshold += imperative_whitelist_signal * 0.5
            # C1 误报治理：白名单匹配（>0.3）时强制 PASS
            if imperative_whitelist_signal > 0.3 and not (keyword_attack_signal > 0 or strong_keyword_attack_signal > 0):
                trust = TrustLevel.LOW
                self.chaos_nursery.append(feat.copy())
                decision = Decision.PASS
            elif fused_anomaly < soft_threshold:
                trust = TrustLevel.LOW
                self.chaos_nursery.append(feat.copy())
                decision = Decision.PASS
            else:
                trust = TrustLevel.UNKNOWN
                decision = Decision.REJECT

        if decision == Decision.PASS and self._luoshu_veto:
            decision = Decision.REJECT
            trust = TrustLevel.UNKNOWN
            if debug_info is not None:
                debug_info["anomaly_signals"].append("luoshu_attack_prototype_match")

        if decision == Decision.PASS and decoded_attack_signal > 0:
            decision = Decision.REJECT
            trust = TrustLevel.UNKNOWN
            if debug_info is not None:
                debug_info["anomaly_signals"].append("decoded_payload_attack")

        if decision == Decision.PASS and keyword_attack_signal > 0 and dist > domain_threshold * 1.8:
            decision = Decision.REJECT
            trust = TrustLevel.UNKNOWN
            if debug_info is not None:
                debug_info["anomaly_signals"].append("keyword_attack")

        # A2 修复：强攻击关键词无视距离条件直接拦截
        # 覆盖 MEDIUM 区域（0.21-0.63）的攻击，即使距离不够远也拦截
        if decision == Decision.PASS and strong_keyword_attack_signal > 0:
            decision = Decision.REJECT
            trust = TrustLevel.UNKNOWN
            if debug_info is not None:
                debug_info["anomaly_signals"].append("strong_keyword_attack")

        # B1 修复：角色扮演越狱检测，无视距离直接拦截
        if decision == Decision.PASS and roleplay_signal > 0:
            decision = Decision.REJECT
            trust = TrustLevel.UNKNOWN
            if debug_info is not None:
                debug_info["anomaly_signals"].append("roleplay_jailbreak")

        # B2 修复：社会工程攻击检测，无视距离直接拦截
        if decision == Decision.PASS and social_engineering_signal > 0:
            decision = Decision.REJECT
            trust = TrustLevel.UNKNOWN
            if debug_info is not None:
                debug_info["anomaly_signals"].append("social_engineering")

        # B3 修复：数据泄露攻击检测，无视距离直接拦截
        if decision == Decision.PASS and data_exfiltration_signal > 0:
            decision = Decision.REJECT
            trust = TrustLevel.UNKNOWN
            if debug_info is not None:
                debug_info["anomaly_signals"].append("data_exfiltration")

        # B4 修复：系统提示词泄露攻击检测，无视距离直接拦截
        if decision == Decision.PASS and system_prompt_leak_signal > 0:
            decision = Decision.REJECT
            trust = TrustLevel.UNKNOWN
            if debug_info is not None:
                debug_info["anomaly_signals"].append("system_prompt_leak")

        # B5 修复：过度代理攻击检测，无视距离直接拦截
        if decision == Decision.PASS and excessive_agency_signal > 0:
            decision = Decision.REJECT
            trust = TrustLevel.UNKNOWN
            if debug_info is not None:
                debug_info["anomaly_signals"].append("excessive_agency")

        # B6 修复：危险命令模式检测，无视距离直接拦截
        if decision == Decision.PASS and dangerous_command_signal > 0:
            decision = Decision.REJECT
            trust = TrustLevel.UNKNOWN
            if debug_info is not None:
                debug_info["anomaly_signals"].append("dangerous_command")

        # B7 修复：训练数据利用 + 危险主题组合检测，无视距离直接拦截
        if decision == Decision.PASS and training_data_exploitation_signal > 0:
            decision = Decision.REJECT
            trust = TrustLevel.UNKNOWN
            if debug_info is not None:
                debug_info["anomaly_signals"].append("training_data_exploitation")

        # B8 修复：Leet speak 编码攻击检测，无视距离直接拦截
        if decision == Decision.PASS and leet_speak_attack_signal > 0:
            decision = Decision.REJECT
            trust = TrustLevel.UNKNOWN
            if debug_info is not None:
                debug_info["anomaly_signals"].append("leet_speak_attack")

        if decision == Decision.REJECT and normalized_benign_signal:
            decision = Decision.PASS
            trust = TrustLevel.LOW
            self.chaos_nursery.append(feat.copy())
            if debug_info is not None:
                debug_info["anomaly_signals"].append("normalized_benign_override")

        if decision == Decision.PASS:
            if isinstance(raw_input, str):
                self._learn_inquiry_patterns(raw_input)
            if trust in (TrustLevel.HIGH, TrustLevel.MEDIUM):
                self._accepted_distances.append(dist)
                self._update_ewma(dist)
                if isinstance(raw_input, str):
                    self._update_domain_char_profile(raw_input)
            if self._luoshu is not None and isinstance(raw_input, str):
                if luoshu_attack_dist < 1.0 or luoshu_safe_dist < 1.0:
                    self._luoshu.learn_safe(luoshu_state)
                else:
                    state = self._luoshu.encode(raw_input)
                    self._luoshu.learn_safe(state)
        elif decision == Decision.REJECT and isinstance(raw_input, str) and trust == TrustLevel.UNKNOWN:
            self._update_rejected_fourgram_profile(raw_input)
            if self._luoshu is not None:
                if luoshu_attack_dist < 1.0 or luoshu_safe_dist < 1.0:
                    self._luoshu.learn_attack(luoshu_state)
                else:
                    state = self._luoshu.encode(raw_input)
                    self._luoshu.learn_attack(state)

        if trust in (TrustLevel.HIGH, TrustLevel.MEDIUM) and len(self.prototypes) > 0:
            lr = self.config.prototype_learning_rate
            self.prototypes[proto_idx] = (1 - lr) * self.prototypes[proto_idx] + lr * feat
            self.prototypes[proto_idx] = self._normalize(self.prototypes[proto_idx])

        if self._should_spawn_prototype():
            self._spawn_prototype()

        if debug_info is not None:
            if dist <= domain_threshold * 0.6:
                debug_info["domain_familiarity"] = "high"
                debug_info["decision_reason"] = "input_matches_known_domain"
            elif dist <= domain_threshold * 1.8:
                debug_info["domain_familiarity"] = "medium"
                if decision == Decision.REJECT:
                    debug_info["decision_reason"] = "anomaly_detected_in_boundary_region"
                    if binary_anomaly >= 0.5:
                        debug_info["anomaly_signals"].append("binary_pattern_anomaly")
                    if fourgram_signal > 0.1:
                        debug_info["anomaly_signals"].append("pattern_similarity_to_rejected")
                    if structural_anomaly > self.config.structural_anomaly_threshold:
                        debug_info["anomaly_signals"].append("structural_anomaly")
                else:
                    debug_info["decision_reason"] = "boundary_input_accepted_with_low_trust"
            else:
                debug_info["domain_familiarity"] = "low"
                if decision == Decision.REJECT:
                    debug_info["decision_reason"] = "input_outside_known_domain_with_anomaly"
                    debug_info["anomaly_signals"].append("distance_too_far")
                    if binary_anomaly >= 0.5:
                        debug_info["anomaly_signals"].append("binary_pattern_anomaly")
                    if fourgram_signal > 0.1:
                        debug_info["anomaly_signals"].append("pattern_similarity_to_rejected")
                else:
                    debug_info["decision_reason"] = "novel_input_accepted_for_nursery"
            if is_learning:
                debug_info["anomaly_signals"].append("learning_context_detected")
            if is_inquiry:
                debug_info["anomaly_signals"].append("inquiry_pattern_detected")

            if self.config.verbose_debug:
                debug_info["signal_strengths"] = {
                    "domain_distance": round(min(1.0, dist / max(1e-6, domain_threshold * 2.0)), 3),
                    "structural_anomaly": round(min(1.0, structural_anomaly / max(1e-6, self.config.structural_anomaly_threshold * 2.0)), 3),
                    "binary_anomaly": round(binary_anomaly, 3),
                    "fourgram_signal": round(fourgram_signal, 3),
                    "leet_speak_signal": round(leet_signal, 3),
                    "homoglyph_signal": round(homoglyph_signal, 3),
                    "luoshu_signal": round(luoshu_signal, 3),
                    "luoshu_attack_dist": round(luoshu_attack_dist, 3),
                    "luoshu_safe_dist": round(luoshu_safe_dist, 3),
                    "language_feature_weight": round(lang_weight, 3),
                    "language_feature_global": round(global_lang_weight, 3),
                    "language_feature_luoshu": round(luoshu_lang_weight, 3),
                }

            self._last_debug_info = debug_info

        return decision, feat, trust, float(dist)

    def _nearest_prototype(self, feat: np.ndarray) -> Tuple[float, int]:
        """查找最近原型，返回(距离, 原型索引)。"""
        if len(self.prototypes) == 0:
            return 2.0, -1

        feat_norm = self._normalize(feat)

        if self._proj_matrix is not None:
            proj_feat = feat_norm @ self._proj_matrix
            proj_feat = self._normalize(proj_feat)
            current_version = len(self.prototypes)
            if self._proj_protos_cache is None or self._proj_protos_version != current_version:
                proj_protos = self.prototypes @ self._proj_matrix
                proj_norms = np.linalg.norm(proj_protos, axis=1, keepdims=True) + 1e-12
                self._proj_protos_cache = proj_protos / proj_norms
                self._proj_protos_version = current_version
            sim = self._proj_protos_cache @ proj_feat
        else:
            sim = self.prototypes @ feat_norm

        best_idx = int(np.argmax(sim))
        if 0 <= best_idx < len(self.prototype_hit_counts):
            self.prototype_hit_counts[best_idx] += 1
        best_sim = float(sim[best_idx])
        dist = 1.0 - best_sim

        noise_std = self.config.prototype_distance_noise
        if noise_std > 0:
            dist += self._rng.normal(0, noise_std)

        return float(max(0.0, dist)), best_idx

    def _init_projection(self) -> Optional[np.ndarray]:
        """初始化高维随机投影矩阵，模糊原型空间边界。"""
        scale = self.config.prototype_projection_scale
        if scale <= 0:
            return None
        rng = np.random.default_rng(seed=_derive_seed(self._key, 982451653))
        K = rng.normal(0, 1, (self.dim, self.dim)).astype(np.float32)
        K = (K + K.T) * 0.5
        P = np.eye(self.dim, dtype=np.float32) + scale * K
        fro_norm = np.linalg.norm(P, "fro")
        if fro_norm > 1e-12:
            P = P / fro_norm * max(1e-10, np.sqrt(self.dim))
        return P

    def _compute_threshold(self) -> float:
        """计算自适应域阈值。

        仅使用被接受的（HIGH/MEDIUM信任）距离进行EWMA初始化，
        防止攻击样本拉低阈值。
        """
        base = self.config.prototype_distance_threshold
        if len(self._accepted_distances) < 5:
            return base

        recent = list(self._accepted_distances)

        if self._ewma_mean is None:
            raw_median = float(np.median(recent))
            self._ewma_mean = max(raw_median, base * 0.4)
            self._ewma_var = float(np.var(recent) + 1e-8)

        dynamic = self._ewma_mean * 1.2
        floor = self.config.threshold_floor
        return float(max(floor, min(dynamic, base * 1.2)))

    def _compute_reject_boundary(self) -> float:
        """计算拒绝边界。

        与域边界不同，拒绝边界不应随 EWMA 自适应，否则攻击者可通过
        low-and-slow 攻击驯化拒绝边界。
        """
        base = self.config.prototype_distance_threshold
        return base * self.config.reject_boundary_multiplier

    def _compute_structural_anomaly(self, text: str, is_inquiry: bool = False,
                                     fourgram_signal: float = 0.0, dist: float = 0.0) -> float:
        """计算结构异常分数：基于统计特征检测异常结构。

        检测维度：全大写比例、冒号密度、特殊字符密度、空格比率、
        中英混合、攻击4-gram重叠密度、距离z-score、古典中文偏离度。
        """
        if not text or len(text) < 3:
            return 0.0

        scores = []
        n = len(text)

        alpha_chars = [c for c in text if c.isalpha()]
        if alpha_chars:
            upper_ratio = sum(1 for c in alpha_chars if c.isupper()) / len(alpha_chars)
            if upper_ratio > 0.25:
                scores.append(min(1.0, (upper_ratio - 0.25) / 0.5))

        colon_count = text.count(':') + text.count(chr(0xFF1A))
        colon_ratio = colon_count / n
        if colon_ratio > 0.015:
            scores.append(min(1.0, (colon_ratio - 0.015) / 0.04))

        excl_count = text.count('!') + text.count(chr(0xFF01))
        excl_ratio = excl_count / n
        if excl_ratio > 0.008:
            scores.append(min(1.0, (excl_ratio - 0.008) / 0.025))

        special = sum(1 for c in text if not c.isalnum() and not c.isspace()
                      and ord(c) < 0x2E80)
        special_ratio = special / n
        if special_ratio > 0.06:
            scores.append(min(1.0, (special_ratio - 0.06) / 0.10))

        space_count = sum(1 for c in text if c == ' ')
        space_ratio = space_count / n
        if space_ratio > 0.3:
            scores.append(min(1.0, (space_ratio - 0.3) / 0.2))

        cn_chars = sum(1 for c in text if '\u4e00' <= c <= '\u9fff')
        en_chars = sum(1 for c in text if c.isascii() and c.isalpha())
        total_lang = cn_chars + en_chars
        if total_lang > 3:
            cn_ratio = cn_chars / total_lang
            en_ratio = en_chars / total_lang
            if cn_ratio > 0.2 and en_ratio > 0.2:
                mix_score = min(cn_ratio, en_ratio) * 2.0
                scores.append(min(1.0, mix_score))

        if self._domain_char_fourgram_profile and len(text) >= 4 and self._rejected_fourgram_profile:
            if not is_inquiry:
                input_fourgrams = {}
                for i in range(len(text) - 3):
                    fg = text[i:i+4].lower()
                    input_fourgrams[fg] = input_fourgrams.get(fg, 0) + 1
                total_fg = sum(input_fourgrams.values())
                if total_fg > 0:
                    rare_total = 0
                    rare_rejected = 0
                    for fg, count in input_fourgrams.items():
                        domain_freq = self._domain_char_fourgram_profile.get(fg, 0.0)
                        if domain_freq < 1e-8:
                            rare_total += count
                            rejected_freq = self._rejected_fourgram_profile.get(fg, 0.0)
                            if rejected_freq > 1e-4:
                                rare_rejected += count
                    if rare_total > 0:
                        overlap_density = rare_rejected / rare_total
                        if overlap_density > 0.15:
                            atk_score = min(1.0, overlap_density * 2.5)
                            scores.append(atk_score)

        if (len(self._accepted_distances) >= 10 and len(self.distance_history) >= 10
                and dist <= self.config.prototype_distance_threshold * 1.8):
            recent_dists = list(self.distance_history)[-50:]
            dist_mean = float(np.mean(recent_dists))
            dist_std = float(np.std(recent_dists)) + 1e-8
            current_dist = self.distance_history[-1] if self.distance_history else 0.0
            z_score = abs(current_dist - dist_mean) / dist_std
            if z_score > 4.0:
                scores.append(min(1.0, (z_score - 4.0) / 3.0))

        if self._domain_char_profile:
            input_profile = self._compute_char_class_vector(text)
            if input_profile:
                has_q_mark = '?' in text or chr(0xFF1F) in text
                if has_q_mark:
                    q_idx = max(text.find('?'), text.find(chr(0xFF1F)))
                    if q_idx >= 0 and q_idx < len(text) - 3:
                        after_q = text[q_idx+1:].strip()
                        if (after_q
                                and not after_q.startswith('?')
                                and not after_q.startswith(chr(0xFF1F))
                                and not after_q.startswith(chr(0xFF01))
                                and not after_q.startswith(chr(0xFF1A))):
                            after_q_ratio = len(after_q) / max(1, n)
                            qtc_score = min(0.6, after_q_ratio * 4.0)
                            if qtc_score > 0.05:
                                scores.append(qtc_score)

                domain_cn_classical = self._domain_char_profile.get('cn_classical', 0.0)
                input_cn_classical = input_profile.get('cn_classical', 0.0)
                input_cn = input_profile.get('cn', 0.0)
                if (input_cn > 0.4 and domain_cn_classical > 0.02
                        and input_cn_classical < 0.05):
                    classical_gap = domain_cn_classical - input_cn_classical
                    length_factor = min(1.0, max(0.0, (n - 8) / 12.0))
                    classical_confidence = min(1.0, self._domain_char_count / 20.0)
                    classical_score = min(1.0, classical_gap * 3.0 * length_factor * classical_confidence)
                    has_q = '?' in text or chr(0xFF1F) in text or chr(0xFF01) in text or chr(0xFF1A) in text
                    if has_q and fourgram_signal <= 0.05:
                        classical_score *= 0.15
                    text_stripped = text.rstrip()
                    if text_stripped and text_stripped[-1] in '也矣焉哉乎':
                        classical_score *= 0.2
                    if classical_score > 0.05:
                        scores.append(classical_score)

        if not scores:
            return 0.0

        max_score = max(scores)
        avg_score = sum(scores) / len(scores)
        return min(1.0, max(max_score, avg_score * 1.5))

    def _update_ewma(self, dist: float):
        """EWMA更新：仅对非异常距离更新，防止攻击样本污染。"""
        if self._ewma_mean is None:
            return

        alpha = self.config.ewma_alpha
        dev = abs(float(dist) - self._ewma_mean) / (np.sqrt(self._ewma_var) + 1e-8)
        if dev < 2.0:
            self._ewma_mean = alpha * float(dist) + (1 - alpha) * self._ewma_mean
            self._ewma_var = alpha * (float(dist) - self._ewma_mean) ** 2 + (1 - alpha) * self._ewma_var

    def _compute_novel_trigram_ratio(self, text: str) -> float:
        """计算字节trigram新颖度：输入的字节模式在已知域中是否见过。

        与语言偏差的区别：语言偏差是静态规则（"英文=域外"），
        而novel_trigram_ratio是数据驱动的——如果英文输入的
        trigram在域中出现过（因为之前有英文良性输入被接纳），
        则新颖度低，不会被误判。
        """
        if not text or not self._domain_trigram_profile or len(text) < 6:
            return 0.0

        data = text.encode('utf-8')
        n = len(data)
        if n < 6:
            return 0.0

        input_trigrams = {}
        for i in range(n - 2):
            tg = (data[i], data[i + 1], data[i + 2])
            input_trigrams[tg] = input_trigrams.get(tg, 0) + 1
        total_tg = sum(input_trigrams.values())
        if total_tg == 0:
            return 0.0

        novel_count = 0
        for tg, count in input_trigrams.items():
            if tg not in self._domain_trigram_profile:
                novel_count += count

        return novel_count / total_tg

    def _compute_rare_fourgram_ratio(self, text: str) -> float:
        """计算字符4-gram罕见度：输入中域内频率极低的4-gram占比。

        与novel_trigram_ratio的区别：
        - trigram基于字节流，fourgram基于字符
        - trigram检测完全未见过的模式，fourgram检测罕见模式
        """
        if not text or not self._domain_char_fourgram_profile or len(text) < 4:
            return 0.0

        input_fourgrams = {}
        for i in range(len(text) - 3):
            fg = text[i:i+4].lower()
            input_fourgrams[fg] = input_fourgrams.get(fg, 0) + 1
        total_fg = sum(input_fourgrams.values())
        if total_fg == 0:
            return 0.0

        rare_count = 0
        for fg, count in input_fourgrams.items():
            domain_freq = self._domain_char_fourgram_profile.get(fg, 0.0)
            if domain_freq < 1e-8:
                rare_count += count

        return rare_count / total_fg

    def _compute_fourgram_signal(self, text: str, is_inquiry: bool = False,
                                 is_learning: bool = False) -> float:
        """四元组双向信号：攻击密度 vs 良性比例。

        攻击信号：输入的罕见4-gram与被拒绝档案重叠 → 正值
        良性信号：输入的罕见4-gram不在被拒绝档案中 → 负值

        基于密度而非计数，避免常见4-gram导致的误判。
        学习/查询上下文提供分级折扣，平衡攻击检测与良性接纳。

        滑动窗口增强：当文本较长时，良性上下文可能稀释攻击密度。
        滑动窗口在局部区域查找攻击模式，取全局和局部的最大攻击密度。
        """
        if not text or not self._domain_char_fourgram_profile or len(text) < 4:
            return 0.0

        if not self._rejected_fourgram_profile:
            return 0.0

        input_fourgrams = {}
        for i in range(len(text) - 3):
            fg = text[i:i+4].lower()
            input_fourgrams[fg] = input_fourgrams.get(fg, 0) + 1
        total_fg = sum(input_fourgrams.values())
        if total_fg == 0:
            return 0.0

        rare_count = 0
        rare_rejected = 0
        rare_not_rejected = 0

        for fg, count in input_fourgrams.items():
            domain_freq = self._domain_char_fourgram_profile.get(fg, 0.0)
            if domain_freq < 1e-8:
                rare_count += count
                rejected_freq = self._rejected_fourgram_profile.get(fg, 0.0)
                if rejected_freq > 1e-4:
                    rare_rejected += count
                else:
                    rare_not_rejected += count

        if rare_count == 0:
            return 0.0

        signal = 0.0

        attack_density = rare_rejected / rare_count if rare_count > 0 else 0.0
        benign_ratio = rare_not_rejected / rare_count if rare_count > 0 else 0.0

        window_attack_density = 0.0
        if len(text) > 40:
            window_attack_density = self._sliding_window_attack_density(text)
            if window_attack_density > attack_density:
                attack_density = window_attack_density

        if attack_density > 0.1:
            attack_signal = min(0.6, attack_density * 1.5)
            if is_learning:
                if attack_density > 0.5:
                    attack_signal *= 0.6
                elif attack_density > 0.2:
                    attack_signal *= 0.4
                elif benign_ratio > 0.6:
                    attack_signal *= 0.2
                else:
                    attack_signal *= 0.4
            elif is_inquiry:
                if attack_density > 0.3:
                    pass
                elif attack_density > 0.2:
                    attack_signal *= 0.7
                elif benign_ratio > 0.6:
                    attack_signal *= 0.3
                else:
                    attack_signal *= 0.5
            signal += attack_signal

        if benign_ratio > 0.4:
            if window_attack_density > 0.3 and not is_learning:
                pass
            elif is_learning:
                signal -= min(0.8, benign_ratio * 0.8)
            else:
                signal -= min(0.2, benign_ratio * 0.2)

        return signal

    def _sliding_window_attack_density(self, text: str, window_size: int = 40,
                                        step: int = 10) -> float:
        """多尺度滑动窗口攻击密度检测 + 跨窗口关联检测。

        当攻击指令被嵌入良性上下文中时，全局攻击密度可能被稀释。
        本方法使用多尺度窗口（20/40/80字符）在文本上滑动，
        计算每个窗口的攻击密度。

        跨窗口关联检测：如果多个窗口都有中等攻击密度（>0.1），
        说明攻击被分散到多个位置。此时累积信号应增强：
        - 3个以上中等密度窗口 → 累积信号 = max_density + 0.15
        - 5个以上中等密度窗口 → 累积信号 = max_density + 0.3

        活性防护哲学：攻击者可以将指令拆分为间隔>80字符的多个片段，
        使每个窗口内攻击密度不足。但多个窗口同时出现中等密度
        本身就是异常信号——正常文本的攻击密度窗口应接近0。
        """
        if not text or not self._domain_char_fourgram_profile or not self._rejected_fourgram_profile:
            return 0.0

        n = len(text)
        if n < 20:
            return 0.0

        max_density = 0.0
        moderate_density_windows = 0

        window_scales = [(20, 5), (40, 10), (80, 20)]
        for ws, st in window_scales:
            if n < ws:
                continue
            for start in range(0, n - ws + 1, st):
                window = text[start:start + ws]
                window_fourgrams = {}
                for i in range(len(window) - 3):
                    fg = window[i:i+4].lower()
                    window_fourgrams[fg] = window_fourgrams.get(fg, 0) + 1
                total_fg = sum(window_fourgrams.values())
                if total_fg == 0:
                    continue

                rare_count = 0
                rare_rejected = 0
                for fg, count in window_fourgrams.items():
                    domain_freq = self._domain_char_fourgram_profile.get(fg, 0.0)
                    if domain_freq < 1e-8:
                        rare_count += count
                        rejected_freq = self._rejected_fourgram_profile.get(fg, 0.0)
                        if rejected_freq > 1e-4:
                            rare_rejected += count

                if rare_count > 0:
                    density = rare_rejected / rare_count
                    if density > max_density:
                        max_density = density
                    if density > 0.1:
                        moderate_density_windows += 1

        if moderate_density_windows >= 5:
            max_density = min(1.0, max_density + 0.3)
        elif moderate_density_windows >= 3:
            max_density = min(1.0, max_density + 0.15)

        return max_density

    def _compute_binary_anomaly(self, text: str) -> float:
        """字节流异常检测：基于字节流内禀统计特性。

        所有输入统一视为字节流，检测信号来自字节流的内禀统计特性：
        1. Shannon 熵异常（低熵重复或异常高熵编码）
        2. 重复字节模式密度（攻击常含重复指令片段）
        3. 控制字符比例（异常控制字符）
        4. 编码特征（Base64/十六进制编码的攻击载荷）
        5. hex字符串熵分析（hex字符分布均匀度，独立信号）

        域内trigram KL散度：跨语言偏差本质上是
        trigram分布的KL散度——中文域的trigram分布与英文输入的
        trigram分布自然不同，KL散度自然高。良性输入的trigram
        虽然也与域不同，但攻击输入的novel_trigram_mass更高。
        """
        if not text:
            return 0.0

        data = text.encode('utf-8')
        n = len(data)
        if n < 4:
            return 0.0

        scores = []

        byte_counts = np.zeros(256, dtype=np.float32)
        for b in data:
            byte_counts[b] += 1
        probs = byte_counts / n
        probs_pos = probs[probs > 0]
        entropy = -float(np.sum(probs_pos * np.log2(probs_pos)))

        if entropy < 2.0:
            scores.append(min(1.0, (2.0 - entropy) / 1.5))
        elif entropy > 7.0:
            scores.append(min(1.0, (entropy - 7.0) / 1.0))

        max_run = 1
        cur_run = 1
        for i in range(1, n):
            if data[i] == data[i - 1]:
                cur_run += 1
                if cur_run > max_run:
                    max_run = cur_run
            else:
                cur_run = 1
        if max_run > 6:
            repeat_score = min(1.0, (max_run - 6) / 10.0)
            scores.append(repeat_score)

        ctrl_count = sum(1 for b in data if b < 32 and b not in (9, 10, 13))
        ctrl_ratio = ctrl_count / n
        if ctrl_ratio > 0.02:
            scores.append(min(1.0, ctrl_ratio * 8.0))

        null_count = data.count(0)
        if null_count > 0:
            scores.append(min(1.0, null_count / n * 20.0))

        if n < 6:
            scores.append(0.2)
        elif n > 3000:
            scores.append(min(0.2, (n - 3000) / 15000.0))

        if re.search(r'[A-Za-z0-9+/]{20,}={0,2}$', text.strip()):
            scores.append(0.5)
        if re.search(r'[A-Za-z0-9+/]{20,}={0,2}', text):
            scores.append(0.35)
        if re.search(r'^(?:[0-9a-fA-F]{2})+$', text.strip()):
            scores.append(0.6)
        if re.search(r'(?:[0-9a-fA-F]{2}\s*){10,}', text):
            scores.append(0.4)
        if re.search(r'(?:\\x[0-9a-fA-F]{2}){4,}', text):
            scores.append(0.5)
        if re.search(r'(?:\\u[0-9a-fA-F]{4}){4,}', text):
            scores.append(0.5)
        if re.search(r'[\x00-\x08\x0e-\x1f]{4,}', text):
            scores.append(0.6)

        if self._domain_trigram_profile and n >= 6:
            input_trigrams = {}
            for i in range(n - 2):
                tg = (data[i], data[i + 1], data[i + 2])
                input_trigrams[tg] = input_trigrams.get(tg, 0) + 1
            total_input_tg = sum(input_trigrams.values())
            if total_input_tg > 0:
                for tg in input_trigrams:
                    input_trigrams[tg] /= total_input_tg

                kl_div = 0.0
                novel_trigram_mass = 0.0
                for tg, p_input in input_trigrams.items():
                    p_domain = self._domain_trigram_profile.get(tg, 0.0)
                    if p_domain < 1e-8:
                        novel_trigram_mass += p_input
                    else:
                        kl_div += p_input * np.log2(p_input / p_domain + 1e-12)

                if novel_trigram_mass > 0.5:
                    novel_score = min(1.0, (novel_trigram_mass - 0.5) / 0.3)
                    scores.append(novel_score * 0.4)

                if kl_div > 3.0:
                    kl_score = min(1.0, (kl_div - 3.0) / 8.0)
                    scores.append(kl_score * 0.3)

        if self._domain_byte_profile is not None:
            upper_count = sum(1 for b in data if 65 <= b <= 90)
            upper_ratio = upper_count / n
            domain_upper = sum(self._domain_byte_profile[b] for b in range(65, 91))
            if domain_upper < 0.02 and upper_ratio > 0.05:
                upper_score = min(1.0, (upper_ratio - 0.05) / 0.10)
                scores.append(upper_score * 0.6)

        if not scores:
            return 0.0

        max_score = max(scores)
        avg_score = sum(scores) / len(scores)
        return min(1.0, max(max_score, avg_score * 1.3))

    def _compute_leet_speak_signal(self, text: str) -> float:
        """字符类一致性检测：数据驱动的leet speak/编码变异检测。

        活性防护哲学：不硬编码"1gn0r3=ignore"的映射规则，而是检测
        字符类不一致的统计特征——正常英文单词中字母和数字不会频繁
        交替出现。当单词内字母-数字转换频率异常高时，表明可能是
        leet speak编码的攻击指令。

        检测逻辑：
        1. 将文本按空格分词
        2. 对每个词计算字母→数字和数字→字母的转换次数
        3. 转换频率 = 转换次数 / 词长
        4. 高转换频率的词占比异常时，产生攻击信号

        这是纯统计信号，不依赖任何语言先验。
        """
        if not text or len(text) < 4:
            return 0.0

        words = text.split()
        if not words:
            return 0.0

        suspicious_words = 0
        total_alpha_words = 0

        for word in words:
            if len(word) < 3:
                continue

            has_alpha = any(c.isalpha() for c in word)
            has_digit = any(c.isdigit() for c in word)

            if not has_alpha:
                continue

            total_alpha_words += 1

            if not has_digit:
                continue

            transitions = 0
            for i in range(1, len(word)):
                prev_is_digit = word[i-1].isdigit()
                curr_is_digit = word[i].isdigit()
                if prev_is_digit != curr_is_digit:
                    transitions += 1

            if len(word) > 2:
                transition_rate = transitions / (len(word) - 1)
                digit_ratio = sum(1 for c in word if c.isdigit()) / len(word)

                if transition_rate > 0.3 and digit_ratio > 0.15:
                    suspicious_words += 1

        if total_alpha_words == 0:
            return 0.0

        suspicious_ratio = suspicious_words / total_alpha_words

        if suspicious_ratio > 0.3:
            signal = min(0.6, suspicious_ratio * 1.5)
            return signal
        elif suspicious_ratio > 0.15:
            return min(0.3, suspicious_ratio * 1.0)

        return 0.0

    def _compute_homoglyph_signal(self, text: str) -> float:
        """Unicode同形符检测：数据驱动的homoglyph替换检测。

        活性防护哲学：不硬编码"а=a"的映射规则，而是检测脚本混用
        的统计异常——正常英文文本不应包含西里尔/希腊等视觉相似
        脚本的字符。当文本中拉丁字母与视觉相似的其他脚本字符
        混合出现时，表明可能是homoglyph替换的攻击指令。

        检测逻辑：
        1. 统计文本中各Unicode脚本块的字符数
        2. 如果拉丁字母和视觉相似脚本（西里尔/希腊）同时出现，
           且视觉相似脚本字符占比异常，产生攻击信号
        3. 信号强度与脚本混用程度成正比

        这是纯统计信号，不依赖任何语言先验。
        """
        if not text or len(text) < 4:
            return 0.0

        latin_count = 0
        cyrillic_count = 0
        greek_count = 0
        total_alpha = 0

        for c in text:
            if '\u0041' <= c <= '\u007A' or '\u00C0' <= c <= '\u024F':
                latin_count += 1
                total_alpha += 1
            elif '\u0400' <= c <= '\u04FF':
                cyrillic_count += 1
                total_alpha += 1
            elif '\u0370' <= c <= '\u03FF':
                greek_count += 1
                total_alpha += 1

        if total_alpha < 4:
            return 0.0

        has_latin = latin_count > 0
        has_confusable = cyrillic_count > 0 or greek_count > 0

        if not has_latin or not has_confusable:
            return 0.0

        confusable_count = cyrillic_count + greek_count
        confusable_ratio = confusable_count / total_alpha

        if confusable_ratio > 0.05 and confusable_count >= 2:
            mix_score = min(1.0, confusable_ratio * 5.0)
            signal = 0.3 + 0.3 * mix_score
            return min(0.7, signal)

        if confusable_ratio > 0.02 and confusable_count >= 1:
            return min(0.3, confusable_ratio * 8.0)

        return 0.0

    def _compute_language_feature_weight(self) -> float:
        """语言特征权重渐进衰减：原型数驱动自动降权。

        活性防护哲学：语言特征（大写比例、冒号密度等）是冷启动阶段的
        临时拐杖。当洛书原型库足够丰富时，系统应自动降低语言特征权重，
        最终完全依赖符号级信号。这不是硬编码的开关，而是数据驱动的
        渐进衰减——原型越多，语言特征越不重要。

        衰减阶段：
        - 阶段一（冷启动）：安全原型<=100 或 攻击原型<=50 → 权重1.0
        - 阶段二（过渡）：安全原型>100 且 攻击原型>50 → 权重0.5
        - 阶段三（成熟）：安全原型>500 且 攻击原型>200 → 权重0.0

        衰减是渐进的：在阶段一到阶段二之间，权重线性插值；
        在阶段二到阶段三之间，权重也线性插值。这避免了突变。
        """
        if self._luoshu is None:
            return 1.0

        safe_count = len(self._luoshu.safe_prototypes)
        attack_count = len(self._luoshu.attack_prototypes)

        cfg = self.config
        safe_thresh = cfg.language_feature_decay_safe_threshold
        attack_thresh = cfg.language_feature_decay_attack_threshold
        safe_full = cfg.language_feature_decay_full_safe
        attack_full = cfg.language_feature_decay_full_attack
        mid_weight = cfg.language_feature_decay_mid_weight

        safe_progress = max(0.0, min(1.0,
            (safe_count - safe_thresh) / max(1, safe_full - safe_thresh)))
        attack_progress = max(0.0, min(1.0,
            (attack_count - attack_thresh) / max(1, attack_full - attack_thresh)))

        progress = min(safe_progress, attack_progress)

        if progress <= 0.0:
            weight = 1.0
        elif progress >= 1.0:
            weight = 0.0
        else:
            weight = 1.0 - progress * (1.0 - mid_weight)

        self._language_feature_weight = weight
        return weight

    def _compute_luoshu_confidence_weight(
        self, attack_dist: float, safe_dist: float
    ) -> float:
        """洛书置信度选择性豁免：逐输入决定语言特征权重。

        活性防护哲学：不是所有输入都需要语言特征。当洛书已经能
        明确判断（强安全或强攻击信号）时，语言特征自动让路；
        只有洛书判断模糊（边界区域）时，才借助语言特征做辅助判断。

        这是"挤走"而非"剥离"——洛书信号越强，语言特征越不需要。
        全局衰减（原型数驱动）和逐输入豁免（信号强度驱动）取较小值，
        确保两个机制协同工作：
        - 全局衰减：原型库越丰富，语言特征整体越不重要
        - 逐输入豁免：对特定输入，洛书信号越强，语言特征越不需要

        安全门槛：洛书必须同时具备安全原型和攻击原型才能豁免。
        如果攻击原型为空，洛书无法判断攻击，不应削弱语言特征。
        如果安全原型为空，洛书无法判断安全，也不应削弱语言特征。
        这防止了冷启动阶段的误豁免。

        豁免阶段：
        - 强信号：attack_dist<0.15 或 safe_dist<0.2 → 权重0.0（完全豁免）
        - 边界信号：attack_dist<0.35 或 safe_dist<0.4 → 权重0.5（降低）
        - 弱信号：其他 → 权重1.0（使用全局衰减值）

        Args:
            attack_dist: 输入与最近攻击原型的距离。
            safe_dist: 输入与最近安全原型的距离。

        Returns:
            逐输入的语言特征权重（0.0~1.0）。
        """
        if self._luoshu is None:
            return 1.0

        if not self._luoshu.safe_prototypes or not self._luoshu.attack_prototypes:
            return 1.0

        cfg = self.config
        exempt_attack = cfg.luoshu_confidence_exempt_attack
        exempt_safe = cfg.luoshu_confidence_exempt_safe
        borderline_attack = cfg.luoshu_confidence_borderline_attack
        borderline_safe = cfg.luoshu_confidence_borderline_safe
        borderline_weight = cfg.luoshu_confidence_borderline_weight

        strong_attack = attack_dist < exempt_attack
        strong_safe = safe_dist < exempt_safe

        if strong_attack or strong_safe:
            return 0.0

        borderline_attack_signal = exempt_attack <= attack_dist < borderline_attack
        borderline_safe_signal = exempt_safe <= safe_dist < borderline_safe

        if borderline_attack_signal or borderline_safe_signal:
            if borderline_attack_signal and borderline_safe_signal:
                return borderline_weight * 0.5
            return borderline_weight

        return 1.0

    def _compute_luoshu_signal(self, text: str) -> float:
        """洛书符号信号：语言无关的纯符号级攻击/良性判断。

        活性防护哲学：洛书信号不依赖任何语言特征，而是基于输入在
        高维符号空间中的位置。它提供三个子信号：
        1. 安全距离信号：输入与安全原型的距离（近=安全，远=可疑）
        2. 攻击距离信号：输入与攻击原型的距离（近=攻击，远=安全）
        3. 局部密度信号：输入附近的安全原型密度（高=安全，低=可疑）

        信号范围：
        - 正值：攻击信号（输入接近攻击原型或远离安全原型）
        - 负值：良性信号（输入接近安全原型且远离攻击原型）
        - 零：无信号（冷启动阶段，原型库为空）
        """
        if self._luoshu is None or not text:
            return 0.0

        state = self._luoshu.encode(text)

        safe_dist = self._luoshu.compute_safe_distance(state)
        attack_dist = self._luoshu.compute_attack_distance(state)
        density = self._luoshu.compute_local_density(state)

        safe_w = self.config.luoshu_safe_distance_weight
        attack_w = self.config.luoshu_attack_distance_weight
        density_w = self.config.luoshu_density_weight

        attack_signal = (1.0 - attack_dist) * attack_w
        safe_signal = (1.0 - safe_dist) * safe_w
        density_signal = (1.0 - density) * density_w

        signal = attack_signal - safe_signal - density_signal

        return max(-0.5, min(0.5, signal))

    def _should_spawn_prototype(self) -> bool:
        """判断是否应孵化新原型。"""
        if len(self.chaos_nursery) < self.config.chaos_nursery_size:
            return False
        if len(self.prototypes) >= self.config.prototype_max_size:
            return False
        return True

    def _spawn_prototype(self):
        """从混沌期候选队列孵化新原型。

        若候选向量过于分散（高方差），说明它们来自不同语义域，
        不应合并为一个原型，此时选择与现有原型均值距离最远的候选。
        """
        candidates = np.array(list(self.chaos_nursery), dtype=np.float32)
        self.chaos_nursery.clear()

        if len(candidates) < 2:
            return

        centroid = np.mean(candidates, axis=0)
        centroid = self._normalize(centroid)
        similarities = np.dot(candidates, centroid)
        mean_sim = float(np.mean(similarities))
        if mean_sim < 0.3:
            return

        if len(self.prototypes) == 0:
            new_proto = np.mean(candidates, axis=0)
        else:
            best_dist = -1.0
            best_idx = 0
            proto_mean = np.mean(self.prototypes, axis=0)
            proto_mean = self._normalize(proto_mean)
            for i in range(len(candidates)):
                d = 1.0 - float(np.dot(self._normalize(candidates[i]), proto_mean))
                if d > best_dist:
                    best_dist = d
                    best_idx = i
            new_proto = candidates[best_idx].copy()

        new_proto = self._normalize(new_proto)
        self.prototypes = np.vstack([self.prototypes, new_proto.reshape(1, -1)])
        self.prototype_hit_counts = np.append(self.prototype_hit_counts, 0)

        if len(self.prototypes) > self.config.prototype_max_size:
            self._merge_prototypes()

    def _merge_prototypes(self):
        """合并过于相似的原型，保护低频原型不被淘汰。

        合并策略：优先合并最相似的一对，但保护命中次数最少的前10%原型
        （这些可能是新孵化的小众域原型，不应被高频原型吞噬）。
        """
        if len(self.prototypes) <= self.config.prototype_max_size:
            return

        merge_threshold = 0.85
        protected_count = max(1, len(self.prototypes) // 10)
        if len(self.prototype_hit_counts) == len(self.prototypes):
            protected_indices = set(np.argsort(self.prototype_hit_counts)[:protected_count])
        else:
            protected_indices = set()

        while len(self.prototypes) > self.config.prototype_max_size:
            sim_matrix = self.prototypes @ self.prototypes.T
            np.fill_diagonal(sim_matrix, -1.0)

            for p in protected_indices:
                sim_matrix[p, :] = -1.0
                sim_matrix[:, p] = -1.0

            i, j = np.unravel_index(np.argmax(sim_matrix), sim_matrix.shape)
            best_sim = float(sim_matrix[i, j])

            if best_sim < merge_threshold:
                candidates = []
                for idx in range(len(self.prototypes)):
                    if idx not in protected_indices:
                        max_sim = float(np.max(np.delete(sim_matrix[idx], idx)))
                        candidates.append((idx, max_sim))

                candidates.sort(key=lambda x: x[1], reverse=True)
                keep = min(self.config.prototype_max_size, len(self.prototypes))
                keep_indices = sorted(list(protected_indices) + [c[0] for c in candidates[:keep - len(protected_indices)]])
                keep_indices = keep_indices[:keep]
                self.prototypes = self.prototypes[keep_indices]
                self.prototype_hit_counts = self.prototype_hit_counts[keep_indices]
                break

            merged = self._normalize(self.prototypes[i] + self.prototypes[j])
            merged_hits = self.prototype_hit_counts[i] + self.prototype_hit_counts[j]
            self.prototypes[i] = merged
            self.prototype_hit_counts[i] = merged_hits
            self.prototypes = np.delete(self.prototypes, j, axis=0)
            self.prototype_hit_counts = np.delete(self.prototype_hit_counts, j)
            protected_indices = {p - 1 if p > j else p for p in protected_indices if p != j}

    @staticmethod
    def _normalize(v: np.ndarray) -> np.ndarray:
        """L2归一化。"""
        norm = np.linalg.norm(v)
        if norm > 1e-12:
            return v / norm
        return v.copy()

    def _is_inquiry_pattern(self, text: str) -> bool:
        """判断输入是否为疑问/查询模式。

        活性防护：疑问模式从域内自动学习，不是硬编码列表。
        已学习的疑问前缀、祈使句前缀、学习上下文均视为查询模式。
        """
        if not text:
            return False

        text_stripped = text.strip()

        has_question_mark = '?' in text_stripped or chr(0xFF1F) in text_stripped
        has_q_particle = any(p in text_stripped for p in '吗呢吧')

        learning_context = self._is_learning_context(text_stripped)

        text_lower = text_stripped.lower()
        is_imperative = False
        if self._domain_imperative_prefixes:
            words = text_lower.split()
            for n in range(1, min(4, len(words) + 1)):
                prefix = ' '.join(words[:n])
                if prefix in self._domain_imperative_prefixes:
                    if self._domain_imperative_prefixes[prefix] >= 2:
                        is_imperative = True
                        break

        learned_inquiry = False
        if self._domain_inquiry_prefixes:
            words = text_lower.split()
            if words:
                for n in range(1, min(5, len(words) + 1)):
                    prefix = ' '.join(words[:n])
                    if prefix in self._domain_inquiry_prefixes:
                        if self._domain_inquiry_prefixes[prefix] >= 2:
                            learned_inquiry = True
                            break

            if not learned_inquiry:
                cn_chars = [c for c in text_stripped if '\u4e00' <= c <= '\u9fff']
                if cn_chars:
                    for n in range(1, min(5, len(cn_chars) + 1)):
                        char_prefix = ''.join(cn_chars[:n])
                        if char_prefix in self._domain_inquiry_prefixes:
                            if self._domain_inquiry_prefixes[char_prefix] >= 2:
                                learned_inquiry = True
                                break

        return has_question_mark or has_q_particle or learned_inquiry or learning_context or is_imperative

    def _is_learning_context(self, text: str) -> bool:
        """判断输入是否为学习/研究上下文。

        活性防护：5维攻击否定信号 + EWMA动态权重学习。
        当输入同时满足高攻击重叠率+高熵+控制字符等攻击特征时，
        否定学习上下文判定，防止攻击者伪装学习场景。

        优先级：明确的学习标记 > 否定信号。当文本包含
        "security class"、"studying"、"learning"等明确标记时，
        优先信任学习意图，因为真正的攻击不会包含这些标记。
        """
        if not text:
            return False
        text_lower = text.lower()
        n = len(text)

        has_explicit_learning_marker = False
        explicit_markers = [
            'security class', 'security course', 'for my thesis',
            'i am studying', 'i am learning', 'i am researching',
            'for my research', 'research paper', 'in my research',
            'i need to understand', 'i want to understand',
            'help me understand', 'in my security',
            'we are learning', 'we are studying',
        ]
        for marker in explicit_markers:
            if marker in text_lower:
                has_explicit_learning_marker = True
                break

        if not has_explicit_learning_marker:
            universal_verbs = {'studying', 'learning', 'researching', 'analyzing',
                              'understand', 'explain', 'describe', 'identify'}
            for verb in universal_verbs:
                if verb in text_lower:
                    has_explicit_learning_marker = True
                    break

        if not has_explicit_learning_marker:
            cn_learning = ['正在研究', '正在学习', '正在分析', '帮我理解', '请解释', '我想了解',
                           '论文', '课程', '研究项目']
            for cn_marker in cn_learning:
                if cn_marker in text_lower:
                    has_explicit_learning_marker = True
                    break

        if has_explicit_learning_marker:
            if self._rejected_fourgram_profile and n >= 4:
                input_fourgrams = {}
                for i in range(len(text) - 3):
                    fg = text[i:i+4].lower()
                    input_fourgrams[fg] = input_fourgrams.get(fg, 0) + 1
                total_fg = sum(input_fourgrams.values())
                if total_fg > 0:
                    rejected_count = 0
                    for fg, count in input_fourgrams.items():
                        if self._rejected_fourgram_profile.get(fg, 0.0) > 1e-4:
                            rejected_count += count
                    overlap_ratio = rejected_count / total_fg if total_fg > 0 else 0.0
                    if overlap_ratio > 0.45:
                        has_explicit_learning_marker = False

                    if has_explicit_learning_marker and len(text) > 40:
                        window_density = self._sliding_window_attack_density(text)
                        if window_density > 0.6:
                            has_explicit_learning_marker = False

        if has_explicit_learning_marker:
            return True

        if self._rejected_fourgram_profile and n >= 4:
            input_fourgrams = {}
            for i in range(len(text) - 3):
                fg = text[i:i+4].lower()
                input_fourgrams[fg] = input_fourgrams.get(fg, 0) + 1
            total_fg = sum(input_fourgrams.values())
            if total_fg > 0:
                rejected_count = 0
                for fg, count in input_fourgrams.items():
                    if self._rejected_fourgram_profile.get(fg, 0.0) > 1e-4:
                        rejected_count += count
                overlap_ratio = rejected_count / max(1, total_fg)

                data = text.encode('utf-8')
                byte_counts = np.zeros(256, dtype=np.float32)
                for b in data:
                    byte_counts[b] += 1
                byte_probs = byte_counts / len(data)
                probs_pos = byte_probs[byte_probs > 0]
                entropy = -float(np.sum(probs_pos * np.log2(probs_pos))) if len(probs_pos) > 0 else 0

                ctrl_count = sum(1 for b in data if b < 32 and b not in (9, 10, 13))
                ctrl_ratio = ctrl_count / max(1, len(data))

                is_very_long = n > 500
                is_very_short = n < 10

                negation_score = 0.0
                if overlap_ratio > 0.3:
                    w_overlap = self._negation_weights.get('overlap', 1.0)
                    negation_score += overlap_ratio * w_overlap
                if entropy > 6.0:
                    w_entropy = self._negation_weights.get('entropy', 1.0)
                    negation_score += (entropy - 6.0) * w_entropy
                if ctrl_ratio > 0.05:
                    w_ctrl = self._negation_weights.get('ctrl', 1.0)
                    negation_score += ctrl_ratio * w_ctrl
                if is_very_long:
                    negation_score += self._negation_weights.get('long', 1.0)
                if is_very_short:
                    negation_score += self._negation_weights.get('short', 1.0)

                if negation_score > 0.7:
                    self._update_negation_weights(
                        overlap_ratio, entropy, ctrl_ratio,
                        is_very_long, is_very_short, True
                    )
                    return False
                self._update_negation_weights(
                    overlap_ratio, entropy, ctrl_ratio,
                    is_very_long, is_very_short, False
                )

        if self._domain_learning_phrases:
            for phrase, count in self._domain_learning_phrases.items():
                if count >= 2 and phrase in text_lower:
                    return True
        has_q = '?' in text or chr(0xFF1F) in text
        if has_q:
            first_word = text_lower.split()[0] if text_lower.split() else ''
            inquiry_first = {'what', 'how', 'why', 'when', 'where', 'who', 'which',
                           'can', 'could', 'would', 'is', 'are', 'do', 'does', 'did'}
            if first_word in inquiry_first:
                return True
        return False

    def _learn_inquiry_patterns(self, text: str):
        """从通过决策的输入中学习疑问/祈使句模式。

        活性防护：疑问模式不是硬编码列表，而是从实际输入中动态学习。
        当某个前缀在通过决策的输入中出现>=2次时，自动标记为疑问前缀。
        """
        if not text or len(text) < 3:
            return

        is_question = ('?' in text or chr(0xFF1F) in text
                       or any(p in text for p in '吗呢吧'))

        if is_question:
            text_lower = text.strip().lower()
            words = text_lower.split()
            if words and len(words) >= 2:
                for n in range(1, min(5, len(words) + 1)):
                    prefix = ' '.join(words[:n])
                    self._domain_inquiry_prefixes[prefix] = (
                        self._domain_inquiry_prefixes.get(prefix, 0) + 1
                    )

            cn_chars = [c for c in text if '\u4e00' <= c <= '\u9fff']
            if cn_chars and len(cn_chars) >= 2:
                for n in range(1, min(5, len(cn_chars) + 1)):
                    char_prefix = ''.join(cn_chars[:n])
                    self._domain_inquiry_prefixes[char_prefix] = (
                        self._domain_inquiry_prefixes.get(char_prefix, 0) + 1
                    )

        if len(self._domain_inquiry_prefixes) > 500:
            sorted_prefixes = sorted(
                self._domain_inquiry_prefixes.items(),
                key=lambda x: x[1],
            )
            self._domain_inquiry_prefixes = dict(sorted_prefixes[250:])

    def _update_rejected_fourgram_profile(self, text: str):
        """更新被拒绝4-gram档案：从被拒绝的输入中动态学习。

        活性防护哲学：被拒绝的4-gram模式不是硬编码的攻击关键词列表，
        而是从实际被拒绝的输入中动态学习。当系统拒绝一个输入时，
        其4-gram模式被记录到被拒绝档案中，后续输入如果包含这些模式，
        攻击密度会升高，从而更容易被检测。

        EWMA平滑：使用指数加权移动平均更新频率，避免单次输入
        对档案产生过大影响。定期裁剪低频4-gram，控制内存使用。
        """
        if not text or len(text) < 4:
            return

        fourgrams = {}
        for i in range(len(text) - 3):
            fg = text[i:i+4].lower()
            fourgrams[fg] = fourgrams.get(fg, 0) + 1
        total_fg = sum(fourgrams.values())
        if total_fg == 0:
            return

        for fg in fourgrams:
            fourgrams[fg] /= total_fg

        alpha = min(0.3, 1.0 / (self._rejected_fourgram_count + 1))
        if not self._rejected_fourgram_profile:
            self._rejected_fourgram_profile = fourgrams
        else:
            for fg, freq in fourgrams.items():
                old = self._rejected_fourgram_profile.get(fg, 0.0)
                self._rejected_fourgram_profile[fg] = old * (1 - alpha) + freq * alpha
            for fg in list(self._rejected_fourgram_profile.keys()):
                if fg not in fourgrams:
                    self._rejected_fourgram_profile[fg] *= (1 - alpha)
                    if self._rejected_fourgram_profile[fg] < 1e-8:
                        del self._rejected_fourgram_profile[fg]
        self._rejected_fourgram_count += 1

        if len(self._rejected_fourgram_profile) > 2000:
            sorted_fgs = sorted(
                self._rejected_fourgram_profile.items(),
                key=lambda x: x[1],
            )
            self._rejected_fourgram_profile = dict(sorted_fgs[1000:])

    def _input_to_vector(self, raw_input: Union[str, Vector]) -> Vector:
        """将输入转换为高维向量。

        字符级Unicode散列：按Unicode码点+位置散列生成向量，
        中英文自然分离（中文码点0x4E00-0x9FFF vs 英文0x20-0x7E）。
        共享语义基底：所有输入共享一个低频正弦基底，确保跨语言
        输入不会完全正交。
        """
        if isinstance(raw_input, np.ndarray):
            return raw_input.astype(np.float32)

        if isinstance(raw_input, str):
            dim = self.dim
            hash_vec = np.zeros(dim, dtype=np.float32)
            for i, ch in enumerate(raw_input):
                code = ord(ch)
                idx = (code * 2654435761 + i * 15485863) % dim
                hash_vec[idx] += 1.0
            for i in range(len(raw_input) - 1):
                bg = raw_input[i:i+2]
                c1 = ord(bg[0])
                c2 = ord(bg[1])
                idx = (c1 * 2654435761 + c2 * 15485863) % dim
                hash_vec[idx] += 0.7
            profile = self._compute_char_class_vector(raw_input)
            if profile and self._domain_char_profile:
                class_keys = ['cn', 'cn_classical', 'en_upper',
                              'en_lower', 'digit', 'punct', 'space']
                for i, key in enumerate(class_keys):
                    if key in profile:
                        domain_val = self._domain_char_profile.get(key, 0.0)
                        deviation = profile[key] - domain_val
                        idx = ((i + 200) * 3624360691) % dim
                        hash_vec[idx] += deviation * 4.0
            n = len(raw_input)
            if n > 0:
                base_seed = int(hashlib.md5(raw_input.encode('utf-8')).hexdigest()[:8], 16) & 0x7FFFFFFF
                base_rng = np.random.default_rng(seed=base_seed)
                base = base_rng.normal(0, 0.3, dim).astype(np.float32)
                hash_vec = hash_vec + base
            norm = np.linalg.norm(hash_vec)
            if norm > 0:
                hash_vec = hash_vec / norm
            return hash_vec

        raise TypeError(f"Unsupported input type: {type(raw_input)}")

    def seed_prototype(self, text: str):
        """播种初始安全域原型。"""
        feat = self._input_to_vector(text)
        feat = self._normalize(feat)
        if len(self.prototypes) == 0:
            self.prototypes = feat.reshape(1, -1)
        else:
            self.prototypes = np.vstack([self.prototypes, feat.reshape(1, -1)])
        self.prototype_hit_counts = np.append(self.prototype_hit_counts, 0)
        self._update_domain_char_profile(text)

    def _update_domain_char_profile(self, text: str):
        """更新域字符/字节/trigram/fourgram档案。

        活性防护：域的字符分布和字节分布不是硬编码的，而是从种子和
        实际输入中动态学习。每次通过决策的输入都会更新域档案，
        使系统逐步适应新的良性模式。

        模式遗忘：基于单调时钟的老化分数（频率×新鲜度），
        超过24小时未见的模式权重衰减，48小时后完全遗忘。
        使用time.monotonic()确保不受系统时钟回拨影响。
        """
        if not text:
            return
        profile = self._compute_char_class_vector(text)
        alpha = min(0.3, 1.0 / (self._domain_char_count + 1))
        if not self._domain_char_profile:
            self._domain_char_profile = profile
        else:
            for key in profile:
                old = self._domain_char_profile.get(key, 0.0)
                self._domain_char_profile[key] = old * (1 - alpha) + profile[key] * alpha
        self._domain_char_count += 1

        data = text.encode('utf-8')
        byte_len = len(data)
        if byte_len == 0:
            return
        byte_freq = np.zeros(256, dtype=np.float32)
        for b in data:
            byte_freq[b] += 1
        byte_freq /= byte_len
        byte_alpha = min(0.3, 1.0 / (self._domain_byte_count + 1))
        if self._domain_byte_profile is None:
            self._domain_byte_profile = byte_freq
        else:
            self._domain_byte_profile = (
                self._domain_byte_profile * (1 - byte_alpha) + byte_freq * byte_alpha
            )
        self._domain_byte_count += 1

        trigrams = {}
        for i in range(byte_len - 2):
            tg = (data[i], data[i + 1], data[i + 2])
            trigrams[tg] = trigrams.get(tg, 0) + 1
        total_tg = sum(trigrams.values())
        if total_tg > 0:
            for tg in trigrams:
                trigrams[tg] /= total_tg
            tg_alpha = min(0.3, 1.0 / (self._domain_trigram_count + 1))
            if not self._domain_trigram_profile:
                self._domain_trigram_profile = trigrams
            else:
                for tg, freq in trigrams.items():
                    old = self._domain_trigram_profile.get(tg, 0.0)
                    self._domain_trigram_profile[tg] = old * (1 - tg_alpha) + freq * tg_alpha
                for tg in list(self._domain_trigram_profile.keys()):
                    if tg not in trigrams:
                        self._domain_trigram_profile[tg] *= (1 - tg_alpha)
                        if self._domain_trigram_profile[tg] < 1e-8:
                            del self._domain_trigram_profile[tg]
            self._domain_trigram_count += 1
            if len(self._domain_trigram_profile) > 5000:
                sorted_tg = sorted(
                    self._domain_trigram_profile.items(),
                    key=lambda x: x[1],
                )
                self._domain_trigram_profile = dict(sorted_tg[2500:])

        fourgrams = {}
        for i in range(len(text) - 3):
            fg = text[i:i+4].lower()
            fourgrams[fg] = fourgrams.get(fg, 0) + 1
        total_fg = sum(fourgrams.values())
        if total_fg > 0:
            for fg in fourgrams:
                fourgrams[fg] /= total_fg
            fg_alpha = min(0.3, 1.0 / (self._domain_fourgram_count + 1))
            if not self._domain_char_fourgram_profile:
                self._domain_char_fourgram_profile = fourgrams
            else:
                for fg, freq in fourgrams.items():
                    old = self._domain_char_fourgram_profile.get(fg, 0.0)
                    self._domain_char_fourgram_profile[fg] = old * (1 - fg_alpha) + freq * fg_alpha
                for fg in list(self._domain_char_fourgram_profile.keys()):
                    if fg not in fourgrams:
                        self._domain_char_fourgram_profile[fg] *= (1 - fg_alpha)
                        if self._domain_char_fourgram_profile[fg] < 1e-8:
                            del self._domain_char_fourgram_profile[fg]
            self._domain_fourgram_count += 1
            if len(self._domain_char_fourgram_profile) > 5000:
                sorted_fg = sorted(
                    self._domain_char_fourgram_profile.items(),
                    key=lambda x: x[1],
                )
                self._domain_char_fourgram_profile = dict(sorted_fg[2500:])

        text_lower = text.lower()
        words = text_lower.split()
        now = time.monotonic()
        if len(words) >= 2:
            for n_w in range(1, min(4, len(words) + 1)):
                prefix = ' '.join(words[:n_w])
                self._domain_imperative_prefixes[prefix] = (
                    self._domain_imperative_prefixes.get(prefix, 0) + 1
                )
                self._pattern_timestamps[('imp', prefix)] = now
        if len(self._domain_imperative_prefixes) > 200:
            sorted_prefixes = sorted(
                self._domain_imperative_prefixes.items(),
                key=lambda x: x[1],
            )
            self._domain_imperative_prefixes = dict(sorted_prefixes[100:])

        if len(words) >= 3:
            for i in range(len(words) - 2):
                for length in range(3, min(7, len(words) - i + 1)):
                    phrase = ' '.join(words[i:i+length])
                    self._domain_learning_phrases[phrase] = (
                        self._domain_learning_phrases.get(phrase, 0) + 1
                    )
                    self._pattern_timestamps[('learn', phrase)] = now
        if len(self._domain_learning_phrases) > 500:
            sorted_phrases = sorted(
                self._domain_learning_phrases.items(),
                key=lambda x: x[1],
            )
            self._domain_learning_phrases = dict(sorted_phrases[250:])

        if now - self._last_forget_time >= self._forget_interval_seconds:
            self._forget_stale_patterns()
            self._last_forget_time = now

    def _forget_stale_patterns(self):
        """基于单调时钟的模式遗忘：频率×新鲜度老化分数。

        使用time.monotonic()确保不受系统时钟回拨影响，
        适用于分布式部署场景。每个模式的老化分数 = 频率 × 新鲜度，
        新鲜度随时间衰减（24小时半衰期），48小时后完全遗忘。
        保留最低数量的高频模式，防止遗忘过度。
        """
        now = time.monotonic()

        if self._domain_imperative_prefixes:
            to_keep = {}
            for prefix, count in self._domain_imperative_prefixes.items():
                last_seen = self._pattern_timestamps.get(('imp', prefix), now)
                age_hours = (now - last_seen) / 3600.0
                freshness = max(0.1, 1.0 - age_hours / 24.0)
                score = count * freshness
                if score >= 1.0:
                    to_keep[prefix] = count
            if len(to_keep) < 20:
                sorted_imp = sorted(
                    self._domain_imperative_prefixes.items(),
                    key=lambda x: x[1],
                    reverse=True
                )
                to_keep = dict(sorted_imp[:20])
            self._domain_imperative_prefixes = to_keep

        if self._domain_learning_phrases:
            to_keep = {}
            for phrase, count in self._domain_learning_phrases.items():
                last_seen = self._pattern_timestamps.get(('learn', phrase), now)
                age_hours = (now - last_seen) / 3600.0
                freshness = max(0.1, 1.0 - age_hours / 24.0)
                score = count * freshness
                if score >= 1.0:
                    to_keep[phrase] = count
            if len(to_keep) < 30:
                sorted_learn = sorted(
                    self._domain_learning_phrases.items(),
                    key=lambda x: x[1],
                    reverse=True
                )
                to_keep = dict(sorted_learn[:30])
            self._domain_learning_phrases = to_keep

        if self._domain_inquiry_prefixes:
            to_keep = {}
            for prefix, count in self._domain_inquiry_prefixes.items():
                last_seen = self._pattern_timestamps.get(('inq', prefix), now)
                age_hours = (now - last_seen) / 3600.0
                freshness = max(0.1, 1.0 - age_hours / 24.0)
                score = count * freshness
                if score >= 1.0:
                    to_keep[prefix] = count
            if len(to_keep) < 20:
                sorted_inq = sorted(
                    self._domain_inquiry_prefixes.items(),
                    key=lambda x: x[1],
                    reverse=True
                )
                to_keep = dict(sorted_inq[:20])
            self._domain_inquiry_prefixes = to_keep

        stale_keys = [k for k, t in self._pattern_timestamps.items()
                      if (now - t) / 3600.0 > 48.0]
        for k in stale_keys:
            del self._pattern_timestamps[k]

    def _update_negation_weights(self, overlap_ratio: float, entropy: float,
                                  ctrl_ratio: float, is_very_long: bool,
                                  is_very_short: bool, was_negated: bool):
        """EWMA动态权重学习：从每次决策中自适应调整否定信号权重。

        活性防护哲学：固定权重是硬编码，动态权重是活性。系统从每次
        决策中学习：如果某个信号在否定学习上下文时贡献大（was_negated=True），
        则增强该信号权重；如果该信号在非否定场景中也频繁触发，
        则适度降低权重，避免过度否定。

        初始权重自适应预训练：收集前30个样本的信号分布，
        使用信号方差自动校准初始权重——方差越大的信号维度
        区分力越强，权重越高。校准后切换到EWMA在线学习。

        预热数据信任门槛：高攻击重叠率的样本不纳入校准数据，
        防止攻击者在预热阶段通过精心构造的输入污染权重校准。
        仅overlap_ratio < 0.5的样本才被视为可信校准数据。

        安全锁：当lock_negation_weights_after_warmup=True且校准完成后，
        调用lock_negation_weights()可锁定权重，后续不再更新。
        防止攻击者在运行时通过大量请求污染权重。
        """
        if self._negation_weights_locked:
            return

        signals = {
            'overlap': overlap_ratio if overlap_ratio > 0.3 else 0.0,
            'entropy': (entropy - 6.0) if entropy > 6.0 else 0.0,
            'ctrl': ctrl_ratio if ctrl_ratio > 0.05 else 0.0,
            'long': 1.0 if is_very_long else 0.0,
            'short': 1.0 if is_very_short else 0.0,
        }

        self._negation_sample_count += 1

        if not self._negation_calibrated:
            if overlap_ratio < 0.5:
                for dim, signal_val in signals.items():
                    self._negation_signal_history[dim].append(signal_val)
                    if len(self._negation_signal_history[dim]) > 200:
                        self._negation_signal_history[dim] = self._negation_signal_history[dim][-100:]
            if self._negation_sample_count >= 30:
                self._calibrate_negation_weights()

        if self._negation_calibrated:
            alpha = 0.05
        else:
            alpha = min(0.3, 1.0 / max(1, self._negation_sample_count))

        for dim, signal_val in signals.items():
            if signal_val > 0:
                old_w = self._negation_weights.get(dim, 1.0)
                if was_negated:
                    new_w = old_w * (1.0 + alpha * signal_val)
                else:
                    new_w = old_w * (1.0 - alpha * 0.3 * signal_val)
                new_w = max(0.05, min(new_w, old_w * 3.0))
                self._negation_weights[dim] = new_w

    def lock_negation_weights(self):
        """锁定否定信号权重，防止运行时污染。

        活性防护哲学：活性不等于无约束。安全管理员在预热完成后
        可以锁定权重，确保系统在受控状态下运行。这是活性防护
        与安全治理的平衡——系统可以从数据中学习，但学习过程
        必须在管理员的控制之下。

        典型使用场景：
        1. 预热完成后调用lock_negation_weights()
        2. 系统进入生产模式，权重不再更新
        3. 若需重新学习，创建新实例重新预热
        """
        self._negation_weights_locked = True
        self._negation_calibrated = True

    def _calibrate_negation_weights(self):
        """从信号历史中自适应校准初始权重。

        校准策略：
        1. 计算每个信号维度的方差（区分力指标）
        2. 方差越大 → 区分力越强 → 权重越高
        3. 使用softmax归一化，将方差映射到[0.1, 5.0]的权重范围
        4. 如果某个维度从未激活（方差=0），保持默认权重1.0

        活性防护哲学：权重不是经验值，而是从数据中自组织涌现。
        """
        variances = {}
        for dim, history in self._negation_signal_history.items():
            if len(history) < 10:
                variances[dim] = 0.0
                continue
            values = [v for v in history if v > 0]
            if len(values) < 3:
                variances[dim] = 0.0
                continue
            mean_val = sum(values) / len(values)
            variance = sum((v - mean_val) ** 2 for v in values) / len(values)
            variances[dim] = variance

        total_var = sum(variances.values())
        if total_var < 1e-10:
            self._negation_calibrated = True
            return

        for dim, var in variances.items():
            if var < 1e-10:
                self._negation_weights[dim] = 1.0
            else:
                relative_importance = var / total_var if total_var > 0 else 0.0
                n_dims = len(variances)
                uniform_weight = 1.0 / n_dims
                if relative_importance > uniform_weight * 2:
                    self._negation_weights[dim] = min(5.0, 1.0 + relative_importance * n_dims * 2.0)
                elif relative_importance > uniform_weight:
                    self._negation_weights[dim] = 1.0 + relative_importance * n_dims
                else:
                    self._negation_weights[dim] = max(0.1, relative_importance * n_dims * 0.5)

        self._negation_calibrated = True

    @staticmethod
    def _compute_char_class_vector(text: str) -> dict:
        """计算字符类分布向量：中文/古典中文/英文/数字/标点/空格。"""
        if not text:
            return {}
        n = len(text)
        cn = sum(1 for c in text if '\u4e00' <= c <= '\u9fff')
        cn_classical = sum(1 for c in text if c in '曰乎矣焉哉尔汝吾乃亦盖夫俱咸悉庶盍曷奚罔殆稷雎鸠')
        en_upper = sum(1 for c in text if c.isascii() and c.isupper())
        en_lower = sum(1 for c in text if c.isascii() and c.islower())
        digit = sum(1 for c in text if c.isdigit())
        punct = sum(1 for c in text if not c.isalnum() and not c.isspace())
        space = sum(1 for c in text if c.isspace())
        return {
            'cn': cn / n,
            'cn_classical': cn_classical / n,
            'en_upper': en_upper / n,
            'en_lower': en_lower / n,
            'digit': digit / n,
            'punct': punct / n,
            'space': space / n,
        }

    @property
    def num_prototypes(self) -> int:
        return len(self.prototypes)
