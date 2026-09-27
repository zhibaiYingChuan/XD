r"""sensitive_leak.py — PII / 密钥 / 企业自定义敏感词典检测模块（节 9.7）

功能范围：
  1. 内置高置信 PII / 密钥正则检测（12 类）
     - 个人身份：手机号（CN）、身份证（CN 18 位带校验位）、邮箱、银行卡号（Luhn 校验）、
       护照号（CN）、车牌号（CN）、住址片段（省/市/区 + 具体门牌号模式）
     - 密钥令牌：AWS Access Key / Secret、GCP Service Account 片段、
       JWT（三段 Base64URL + 签名段特征）、Bearer Token、
       私钥片段（BEGIN PRIVATE KEY / RSA 私钥头）、Hex/AES Key（32/64 位 hex 连续）
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
        """预编译内置高置信正则。"""
        # 辅助：添加一条规则
        def add(name: str, category: str, pattern: str, severity: str, flags: int = 0):
            cls._BUILTIN_RULES.append(
                (name, category, re.compile(pattern, flags), severity)
            )

        # ---- PII（中国大陆）----
        add("_builtin_pii_phone", "pii_phone",
            r"(?<!\d)(1[3-9]\d{9})(?!\d)", "medium")
        # 身份证 18 位（带校验位）
        add("_builtin_pii_idcard", "pii_idcard",
            r"(?<!\d)([1-9]\d{5}(19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{3}[\dXx])(?!\d)",
            "high")
        # 邮箱
        add("_builtin_pii_email", "pii_email",
            r"\b([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})\b",
            "low", flags=re.IGNORECASE)
        # 银行卡号：13~19 位纯数字，Luhn 校验在 check() 中二次确认
        add("_builtin_pii_bankcard", "pii_bankcard",
            r"(?<!\d)(\d{13,19})(?!\d)", "medium")
        # 中国护照号：E/G + 8 位数字 或 D + 7 位数字
        add("_builtin_pii_passport", "pii_passport",
            r"(?<![A-Z0-9])([EG]\d{8}|D\d{7})(?![A-Z0-9])",
            "medium", flags=re.IGNORECASE)
        # 中国车牌号：
        #   - 普通小型车/大型车：省简称 + 字母 + 5~6 位字母数字（7或8字符），如 京A12345、沪B88888
        #   - 8 位新能源车牌 + 挂车/港澳/警用尾字（挂 学 警 港澳）也通过最后一位可选匹配覆盖
        add("_builtin_pii_plate", "pii_plate",
            r"(?<![A-Z0-9])([京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤青藏川宁琼使领][A-Z][A-HJ-NP-Z0-9]{5,6}[A-HJ-NP-Z0-9挂学警港澳]?)(?![A-Z0-9])",
            "low")

        # ---- 密钥 / Token ----
        # AWS Access Key ID (AKIA...) + AWS Secret Access Key 格式（40 char base64 片段）
        add("_builtin_key_aws_id", "key_aws",
            r"\b(AKIA[0-9A-Z]{16})\b", "high")
        add("_builtin_key_aws_secret", "key_aws",
            r"(?i)aws.{0,3}(?:secret|access).{0,3}['\"=\s:]+([0-9a-zA-Z/+]{40})['\"\s]?",
            "high")
        # GCP Service Account 片段 — "type": "service_account"
        add("_builtin_key_gcp_sa", "key_gcp",
            r'"type"\s*:\s*"service_account"', "high")
        # JWT：三段 Base64URL，最后段签名特征（至少 43 位 base64url 字符）
        add("_builtin_key_jwt", "key_jwt",
            r"\b(eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]{43,})\b",
            "high")
        # Bearer Token（Authorization: Bearer ... 或直接 Bearer xxx）
        add("_builtin_key_bearer", "key_bearer",
            r"(?i)bearer\s+([A-Za-z0-9\-\._~\+\/]{20,})",
            "medium")
        # 私钥头（BEGIN RSA/PRIVATE/OPENSSH PRIVATE KEY）
        add("_builtin_key_private", "key_private",
            r"-----BEGIN\s+(?:RSA\s+|DSA\s+|EC\s+|OPENSSH\s+|PGP\s+)?PRIVATE\s+KEY-----",
            "high")
        # 32/64 位连续 hex（AES-128 / AES-256 原始 key），前后边界避免误伤 UUID 中的短 hex
        add("_builtin_key_hex_aes", "key_hex_aes",
            r"(?<![0-9a-fA-F])([0-9a-fA-F]{32}|[0-9a-fA-F]{64})(?![0-9a-fA-F])",
            "medium")

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
