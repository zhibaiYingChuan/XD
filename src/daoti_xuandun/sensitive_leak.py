r"""sensitive_leak.py — PII / 密钥 / 企业自定义敏感词典检测模块（节 9.7）

功能范围：
  1. 内置高置信 PII / 密钥正则检测（12 类）
     - 个人身份：手机号（CN）、身份证（CN 18 位带校验位）、邮箱、银行卡号（Luhn 校验）、
       护照号（CN）、车牌号（CN）、住址片段（省/市/区 + 具体门牌号模式）
     - 密钥令牌：AWS Access Key / Secret、GCP Service Account 片段、
       JWT（三段 Base64URL + 签名段特征）、Bearer Token、
       PEM 私钥块（头 + 密钥体）、证书/公钥块、Hex/AES Key（32/64 位 hex 连续）
  2. 企业自定义词典：关键词 + 自定义正则，热加载 + JSON 持久化，
     运行时通过 XuanDun.add_sensitive_pattern / remove_sensitive_pattern 调用
  3. 检测结果：返回 (hit, category, matched_text, severity) 四元组，
     severity ∈ ("high"|"medium"|"low")，high→拦截 / medium→打码 / low→告警
     high：身份证、私钥、JWT、AWS Secret；medium：手机号、银行卡、Bearer；low：邮箱、车牌号
  4. Luhn 校验（银行卡）+ 身份证校验位（ISO 7064:1983.MOD 11-2）减少误报

使用方式：
  from daoti_xuandun.sensitive_leak import SensitiveLeakDetector
  detector = SensitiveLeakDetector(custom_dict_path="/data/sensitive_dict.json")
  detector.add_keyword("project_internal_foo", category="internal", severity="medium")
  detector.add_regex(r"ORDER-[A-Z]{2}-\d{8}", name="order_no", category="internal", severity="medium")
  hit, cat, matched, sev = detector.check(user_text)
  if hit and sev in ("high", "medium"):
      redacted = detector.redact(user_text)  # 将匹配段替换为 [REDACTED:<cat>]

约束：
  - 纯标准库实现（re / json / pathlib），不新增第三方依赖
  - 所有正则都用预编译，check() 单次调用复杂度 O(N_regex + N_keywords)
  - 自定义正则必须 try/except 捕获 re.error，防止企业用户写错正则导致崩溃
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ============================================================
# 数据结构
# ============================================================

@dataclass
class SensitivePattern:
    """企业自定义敏感模式。"""
    name: str
    kind: str              # "keyword" | "regex"
    payload: str           # 关键词字符串 / 正则表达式
    category: str          # 分类标签，如 "internal"、"customer"
    severity: str          # "high" | "medium" | "low"
    case_sensitive: bool = False
    enabled: bool = True


@dataclass
class SensitiveHit:
    """单次敏感检测命中。"""
    category: str          # 命中的类型
    matched_text: str      # 匹配到的原文片段
    severity: str          # "high" | "medium" | "low"
    pattern_name: str      # 命中的规则名（内置规则用 _builtin_* 前缀）
    start: int             # 原文起始偏移
    end: int               # 原文结束偏移


# ============================================================
# 校验函数（降低误报）
# ============================================================

def _luhn_check(number: str) -> bool:
    """Luhn 算法校验（银行卡号/IMEI）。返回 True=校验通过。"""
    if not number.isdigit():
        return False
    digits = [int(d) for d in number]
    # 从右往左，偶数位 ×2，超过 9 减 9
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _cn_id_checksum_valid(id_no: str) -> bool:
    """中国身份证 18 位校验位验证（ISO 7064 MOD 11-2）。"""
    if len(id_no) != 18:
        return False
    weights = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
    check_map = {'0': '1', '1': '0', '2': 'X', '3': '9', '4': '8',
                 '5': '7', '6': '6', '7': '5', '8': '4', '9': '3', '10': '2'}
    try:
        total = sum(int(id_no[i]) * weights[i] for i in range(17))
    except ValueError:
        return False
    expected = check_map[str(total % 11)]
    actual = id_no[17].upper()
    return actual == expected


# ============================================================
# 检测器核心
# ============================================================

class SensitiveLeakDetector:
    """节 9.7 — 敏感信息泄露检测（内置 + 企业自定义）。"""

    # 内置规则清单（所有正则都用 (?i) 或 re.IGNORECASE 控制大小写）
    # category 约定：
    #   pii_phone / pii_idcard / pii_email / pii_bankcard / pii_passport / pii_plate / pii_address
    #   key_aws / key_gcp / key_jwt / key_bearer / key_private / key_hex_aes
    _BUILTIN_RULES: List[Tuple[str, str, re.Pattern, str]] = []

    def __init__(self, custom_dict_path: Optional[str] = None):
        # 1) 初始化内置规则
        if not self._BUILTIN_RULES:
            self._init_builtin_rules()

        # 2) 企业自定义模式
        self.custom_patterns: Dict[str, SensitivePattern] = {}
        self._custom_regex_cache: Dict[str, re.Pattern] = {}

        # 持久化路径：优先环境变量 XUANDUN_DATA_DIR，否则走传入路径，最后默认 ./data
        if custom_dict_path is None:
            base = os.environ.get("XUANDUN_DATA_DIR", "./data")
            self._dict_path = Path(base) / "sensitive_dict.json"
        else:
            self._dict_path = Path(custom_dict_path)
        self._dict_path.parent.mkdir(parents=True, exist_ok=True)

        # 3) 加载已持久化的自定义词典
        self._load_custom_dict()

    # ----------------------------------------------------------
    # 内置规则初始化（class 级别只做一次）
    # ----------------------------------------------------------
    @classmethod
    def _init_builtin_rules(cls):
        """预编译内置高置信正则。

        ★★ 2026-11-13（全局收敛）：凡「凭证形态」的判据全部来自
          ``daoti_xuandun/credentials.py``（唯一真源），本文件不再手写。
          旧实现内联了 AWK/JWT/Bearer/私钥/hex 五类正则，
          与请求侧、响应侧、YAML、输出护栏各写一份且已漂移：
          例如 JWT 这里要求签名 ≥43 位、响应侧只认两段；
          银行卡这里 13–19 位无校验、请求侧是 15–19 位 + Luhn。
          现在统一，任何判据改动只需改真源。

        ★ 分类名与严重级也来自真源的 ``leak_category`` / ``leak_severity``：
          它们允许与请求侧不同（两侧「严重」的含义不同 ——
          请求侧 high = 禁止外发，这里 high = 拦截、medium = 打码），
          但差异必须写在**声明**里，不能在本文件另维护一张映射表。
          上一版在这里写死 `_CATEGORY_MAP`，结果把 key_hex_aes /
          key_bearer / key_gcp 静默改名成 key_api / key_aws，
          历史日志的分类统计会突变。

        ★ 校验器在这里仍然生效：逐条 `spec.find()` 而非合成正则，
          所以身份证 MOD 11-2、银行卡 Luhn 都还在。
        """
        from daoti_xuandun import credentials as reg

        for spec in reg.SPECS:
            cls._BUILTIN_RULES.append(
                (
                    f"_builtin_{spec.key}",
                    spec.leak_category,
                    spec.compile(),
                    spec.leak_severity,
                )
            )

    #: 兼容旧代码：部分调用方按 name 取规则
    _BUILTIN_RULES: List[Tuple[str, str, re.Pattern, str]] = []

    @classmethod
    def _init_builtin_rules_legacy_removed(cls):  # pragma: no cover - 占位
        """历史实现已删除，保留名字只为让旧调用方明确报错。"""
        raise RuntimeError(
            "内联判据已迁移到 daoti_xuandun.credentials.SPECS，请改用规则表"
        )


    # ----------------------------------------------------------
    # 企业自定义词典
    # ----------------------------------------------------------
    def _load_custom_dict(self) -> None:
        """从 JSON 文件加载自定义词典。"""
        if not self._dict_path.exists():
            return
        try:
            raw = json.loads(self._dict_path.read_text(encoding="utf-8"))
            patterns = raw.get("patterns", []) if isinstance(raw, dict) else raw
            for item in patterns:
                try:
                    p = SensitivePattern(**item)
                    self._register_custom(p, persist=False)
                except Exception:
                    # 单条坏掉就跳过，不要全部失败
                    continue
        except Exception:
            # 文件损坏时静默跳过，避免启动失败
            return

    def _save_custom_dict(self) -> None:
        """将自定义词典持久化到 JSON。"""
        payload = {
            "version": 1,
            "generated_at": __import__("datetime").datetime.now().isoformat(timespec="seconds"),
            "patterns": [asdict(p) for p in self.custom_patterns.values() if p.enabled],
        }
        self._dict_path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    def _register_custom(self, p: SensitivePattern, *, persist: bool) -> Tuple[bool, str]:
        """注册一条自定义模式。"""
        # 正则要编译，错了就拒绝
        if p.kind == "regex":
            try:
                flags = 0 if p.case_sensitive else re.IGNORECASE
                self._custom_regex_cache[p.name] = re.compile(p.payload, flags)
            except re.error as e:
                return False, f"正则编译失败：{e}"
        elif p.kind == "keyword":
            if not p.payload.strip():
                return False, "关键词不能为空"
        else:
            return False, f"未知的 pattern.kind: {p.kind}"

        self.custom_patterns[p.name] = p
        if persist:
            self._save_custom_dict()
        return True, "ok"

    def add_keyword(self, name: str, keyword: str, *, category: str = "custom",
                    severity: str = "medium", case_sensitive: bool = False) -> Tuple[bool, str]:
        """新增一条关键词模式。"""
        if not name.strip():
            return False, "name 不能为空"
        p = SensitivePattern(
            name=name, kind="keyword", payload=keyword,
            category=category, severity=severity,
            case_sensitive=case_sensitive, enabled=True,
        )
        return self._register_custom(p, persist=True)

    def add_regex(self, name: str, pattern: str, *, category: str = "custom",
                  severity: str = "medium", case_sensitive: bool = False) -> Tuple[bool, str]:
        """新增一条正则模式。"""
        if not name.strip():
            return False, "name 不能为空"
        p = SensitivePattern(
            name=name, kind="regex", payload=pattern,
            category=category, severity=severity,
            case_sensitive=case_sensitive, enabled=True,
        )
        return self._register_custom(p, persist=True)

    def remove_pattern(self, name: str) -> bool:
        """删除一条自定义模式（name 不存在返回 False）。"""
        existed = name in self.custom_patterns
        if existed:
            del self.custom_patterns[name]
            self._custom_regex_cache.pop(name, None)
            self._save_custom_dict()
        return existed

    def list_patterns(self) -> List[Dict[str, Any]]:
        """返回当前所有自定义模式（用于 API 展示）。"""
        return [asdict(p) for p in self.custom_patterns.values()]

    # ----------------------------------------------------------
    # 检测核心
    # ----------------------------------------------------------
    def check(self, text: str) -> Tuple[bool, Optional[SensitiveHit]]:
        """检测文本是否含敏感信息。

        返回：
            (hit: bool, first_hit: SensitiveHit | None)
            只返回第一条最高严重级别的命中（high > medium > low），
            避免长文本反复扫描带来的性能开销。
        """
        if not isinstance(text, str) or not text:
            return False, None

        # 按严重级别分层扫描：先 high → 再 medium → 再 low
        severity_rank = {"high": 0, "medium": 1, "low": 2}
        best_hit: Optional[SensitiveHit] = None

        # ---- 内置规则 ----
        for name, category, pattern, severity in self._BUILTIN_RULES:
            for m in pattern.finditer(text):
                matched = m.group(1) if m.lastindex else m.group(0)
                start, end = m.span(1) if m.lastindex else m.span(0)

                # 二次校验（降低误报）：身份证 + 银行卡
                if category == "pii_idcard" and not _cn_id_checksum_valid(matched):
                    continue
                if category == "pii_bankcard" and not _luhn_check(matched):
                    continue
                # 手机号附加：不要匹配到 11 位纯数字内部编号（如订单号 13xxxxxxxxx）
                #   已通过 (?<!\d)(?!\d) 字边界保证，跳过

                hit = SensitiveHit(
                    category=category, matched_text=matched, severity=severity,
                    pattern_name=name, start=start, end=end,
                )
                if best_hit is None or severity_rank[severity] < severity_rank[best_hit.severity]:
                    best_hit = hit
                    if severity == "high":
                        # 已命中最高级别，直接返回
                        return True, best_hit

        # ---- 企业自定义规则 ----
        for p in self.custom_patterns.values():
            if not p.enabled:
                continue
            if p.kind == "keyword":
                needle = p.payload
                if p.case_sensitive:
                    idx = text.find(needle)
                    found = idx >= 0
                else:
                    idx = text.lower().find(needle.lower())
                    found = idx >= 0
                if found:
                    start, end = idx, idx + len(needle)
                    matched = text[start:end]
                else:
                    continue
            elif p.kind == "regex":
                rpat = self._custom_regex_cache.get(p.name)
                if rpat is None:
                    continue
                m = rpat.search(text)
                if m is None:
                    continue
                matched = m.group(1) if m.lastindex else m.group(0)
                start, end = m.span(1) if m.lastindex else m.span(0)
            else:
                continue

            sev = p.severity if p.severity in severity_rank else "medium"
            hit = SensitiveHit(
                category=p.category, matched_text=matched, severity=sev,
                pattern_name=p.name, start=start, end=end,
            )
            if best_hit is None or severity_rank[sev] < severity_rank[best_hit.severity]:
                best_hit = hit
                if sev == "high":
                    return True, best_hit

        return (best_hit is not None), best_hit

    # ----------------------------------------------------------
    # 打码（medium 级别处置）
    # ----------------------------------------------------------
    def redact(self, text: str) -> str:
        """将文本中所有命中的敏感片段替换为 [REDACTED:<category>]。

        注意：为保证幂等性，redact 会重新扫描所有命中并全部替换，
        不只替换 check() 返回的第一条。
        """
        if not isinstance(text, str) or not text:
            return text
        # 收集所有命中区间，按 start 排序后从后往前替换（避免偏移错乱）
        hits: List[SensitiveHit] = []

        # 内置
        for name, category, pattern, severity in self._BUILTIN_RULES:
            for m in pattern.finditer(text):
                matched = m.group(1) if m.lastindex else m.group(0)
                if category == "pii_idcard" and not _cn_id_checksum_valid(matched):
                    continue
                if category == "pii_bankcard" and not _luhn_check(matched):
                    continue
                s, e = (m.span(1) if m.lastindex else m.span(0))
                hits.append(SensitiveHit(category, matched, severity, name, s, e))

        # 自定义
        for p in self.custom_patterns.values():
            if not p.enabled:
                continue
            if p.kind == "keyword":
                needle = p.payload
                start = 0
                haystack = text if p.case_sensitive else text.lower()
                needle_find = needle if p.case_sensitive else needle.lower()
                while True:
                    idx = haystack.find(needle_find, start)
                    if idx < 0:
                        break
                    hits.append(SensitiveHit(
                        p.category, text[idx:idx + len(needle)],
                        p.severity if p.severity in ("high", "medium", "low") else "medium",
                        p.name, idx, idx + len(needle),
                    ))
                    start = idx + 1
            elif p.kind == "regex":
                rpat = self._custom_regex_cache.get(p.name)
                if rpat is None:
                    continue
                for m in rpat.finditer(text):
                    matched = m.group(1) if m.lastindex else m.group(0)
                    s, e = m.span(1) if m.lastindex else m.span(0)
                    sev = p.severity if p.severity in ("high", "medium", "low") else "medium"
                    hits.append(SensitiveHit(p.category, matched, sev, p.name, s, e))

        if not hits:
            return text
        # 去重并按 end 倒序替换
        unique = sorted({(h.start, h.end, h.category) for h in hits}, key=lambda x: -x[1])
        result = text
        for s, e, cat in unique:
            result = result[:s] + f"[REDACTED:{cat}]" + result[e:]
        return result
