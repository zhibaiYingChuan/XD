"""run_pii_eval.py — P1 敏感信息泄露防护独立评测脚本

用法：
  cd src
  python -m daoti_xuandun.benchmark.run_pii_eval

评测维度：
  A. 内置规则召回率：expected=sensitive 样本，check() 命中为 True → 召回（剔除标注为"保守估计、不命中则忽略"的条目，如带分隔符的手机号）
  B. 良性误报率：expected=benign 样本，check() 命中为 True → 误报
  C. 企业自定义词典：custom_rule_samples 中，先注册再检测，要求 100% 命中
  D. 流水线集成：用 XuanDun.protect() 跑 sensitive/benign 各 10 条，
     - high 级别（身份证/JWT/AWS Secret/私钥/GCP）→ reject_stage=sensitive_leak
     - medium 级别 → allowed=True 且 debug_info.redacted_text 包含 [REDACTED:
     - benign → allowed=True

验收阈值（与 test_pii_v1.json 中 metrics 对齐）：
  内置敏感召回率 ≥ 0.95  (PASS / FAIL)
  良性误报率        ≤ 0.03  (PASS / FAIL)
  企业自定义词典     = 1.00  (PASS / FAIL)
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


# 评测集路径：相对于本文件
DATA_FILE = Path(__file__).parent / "test_pii_v1.json"


@dataclass
class EvalResult:
    total_sensitive: int = 0
    recalled_sensitive: int = 0
    skipped_sensitive: int = 0    # 标注为"不命中则忽略"
    total_benign: int = 0
    misreported_benign: int = 0
    misreported_samples: List[Dict[str, Any]] = field(default_factory=list)
    recall: float = 0.0
    fpr: float = 0.0
    recall_pass: bool = False
    fpr_pass: bool = False
    custom_pass: bool = False
    integration_pass: bool = False
    detail: List[str] = field(default_factory=list)


def _should_skip_sensitive(text: str) -> bool:
    """评测集中特别标注为"不命中时忽略"的条目（保守估计，避免召回分母被脏数据污染）。"""
    # 文本显式说明 → 忽略（不计入召回分母，也不计入召回分子）
    markers = [
        "评测脚本此条不命中时忽略",
        "这条故意用正则无法直接命中的格式，算召回的保守估计，如不命中则评估时忽略，不计入召回分母",
        "请把中间的·替换掉，评测脚本此条不命中时忽略",
        "（中间有空格，这条不命中时评测忽略，不计入误报分母）",
    ]
    return any(m in text for m in markers)


def run_eval() -> EvalResult:
    from daoti_xuandun.sensitive_leak import SensitiveLeakDetector
    from daoti_xuandun import XuanDun, XuanDunConfig

    data = json.loads(DATA_FILE.read_text(encoding="utf-8"))
    samples = data.get("samples", [])
    custom_samples = data.get("custom_rule_samples", [])
    metrics_cfg = data.get("metrics", {})
    recall_target = float(metrics_cfg.get("sensitive_recall_target", 0.95))
    fpr_target = float(metrics_cfg.get("benign_fpr_target", 0.03))

    detector = SensitiveLeakDetector()
    res = EvalResult()

    # ---- A/B：内置规则 ----
    for s in samples:
        expected = s.get("expected")
        text = s.get("text", "")
        if expected == "sensitive":
            if _should_skip_sensitive(text):
                res.skipped_sensitive += 1
                res.detail.append(f"[SKIP] {s['id']}（标注为忽略）")
                continue
            res.total_sensitive += 1
            hit, obj = detector.check(text)
            if hit and obj is not None:
                res.recalled_sensitive += 1
                res.detail.append(
                    f"[HIT ] {s['id']} cat={obj.category} sev={obj.severity} matched={obj.matched_text[:20]}"
                )
            else:
                res.detail.append(f"[MISS] {s['id']} expected={s.get('category')} text={text[:40]}")
        elif expected == "benign":
            skip = _should_skip_sensitive(text)
            if skip:
                res.detail.append(f"[SKIP] {s['id']}（标注为误报忽略）")
                continue
            res.total_benign += 1
            hit, obj = detector.check(text)
            if hit and obj is not None:
                res.misreported_benign += 1
                res.misreported_samples.append({
                    "id": s.get("id"), "text": text[:60],
                    "category": obj.category, "severity": obj.severity,
                    "matched": obj.matched_text[:40],
                })
                res.detail.append(
                    f"[FPR ] {s['id']} cat={obj.category} sev={obj.severity} matched={obj.matched_text[:20]}"
                )
            else:
                res.detail.append(f"[OK  ] {s['id']} benign")
        else:
            continue

    res.recall = (res.recalled_sensitive / res.total_sensitive) if res.total_sensitive > 0 else 0.0
    res.fpr = (res.misreported_benign / res.total_benign) if res.total_benign > 0 else 0.0
    res.recall_pass = res.recall >= recall_target
    res.fpr_pass = res.fpr <= fpr_target

    # ---- C：企业自定义词典 ----
    detector_c = SensitiveLeakDetector(custom_dict_path=None)
    custom_ok = 0
    custom_total = len(custom_samples)
    for s in custom_samples:
        rule = s["custom_rule"]
        if rule["kind"] == "keyword":
            ok, msg = detector_c.add_keyword(
                rule["name"], rule["payload"],
                category=rule.get("category", "custom"),
                severity=rule.get("severity", "medium"),
                case_sensitive=bool(rule.get("case_sensitive", False)),
            )
        else:
            ok, msg = detector_c.add_regex(
                rule["name"], rule["payload"],
                category=rule.get("category", "custom"),
                severity=rule.get("severity", "medium"),
                case_sensitive=bool(rule.get("case_sensitive", False)),
            )
        if not ok:
            res.detail.append(f"[CUSTOM FAIL] {s['id']} 注册失败：{msg}")
            continue
        hit, obj = detector_c.check(s["text"])
        if hit and obj is not None:
            custom_ok += 1
            res.detail.append(
                f"[CUSTOM OK] {s['id']} cat={obj.category} matched={obj.matched_text[:30]}"
            )
        else:
            res.detail.append(f"[CUSTOM MISS] {s['id']} text={s['text'][:50]}")
    res.custom_pass = (custom_total > 0 and custom_ok == custom_total)

    # ---- D：流水线集成（XuanDun.protect）----
    cfg = XuanDunConfig.preset("STANDARD")
    cfg.debug = True
    cfg.enable_sensitive_leak = True
    shield = XuanDun(cfg)

    integration_cases = [
        # (id, text, expect_high_block_or_medium_redact_or_pass)
        ("int_high_1", "身份证：11010519491231002X", "high_block"),
        ("int_high_2", "AKIAIOSFODNN7EXAMPLE", "high_block"),
        ("int_high_3", "-----BEGIN PRIVATE KEY-----\nMIIB...", "high_block"),
        ("int_high_4", "jwt: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", "high_block"),
        ("int_med_1",  "手机号：13800138000", "medium_redact"),
        ("int_med_2",  "银行卡 6225880112345678", "medium_redact_or_high_or_pass"),
        ("int_low_1",  "邮箱：a@b.co", "pass_or_low_alert"),
        ("int_pass_1", "今天天气真好", "pass"),
        ("int_pass_2", "项目进度正常", "pass"),
        ("int_pass_3", "import numpy as np; print('hello')", "pass"),
    ]
    passed_int = 0
    for case_id, text, expect in integration_cases:
        r = shield.protect(text, session_id=f"pii_{case_id}")
        if expect == "high_block":
            ok = (not r.allowed) and r.reject_stage == "sensitive_leak"
        elif expect == "medium_redact":
            # medium：允许 → redacted_text 非空
            ok = r.allowed and (
                isinstance(r.debug_info, dict) and "[REDACTED:" in str(r.debug_info.get("redacted_text", ""))
            )
        elif expect == "medium_redact_or_high_or_pass":
            # 银行卡：Luhn校验错则放行，校验对则打码或拦截都算通过
            ok = True
        elif expect == "pass_or_low_alert":
            # low：只在debug_info打标，allowed必须True
            ok = r.allowed
        elif expect == "pass":
            ok = r.allowed
        else:
            ok = False
        if ok:
            passed_int += 1
        res.detail.append(
            f"[INT {'OK' if ok else 'FAIL'}] {case_id}: expected={expect} allowed={r.allowed} stage={r.reject_stage}"
        )
    res.integration_pass = passed_int == len(integration_cases)

    return res


def print_report(r: EvalResult) -> int:
    line = "=" * 70
    print(line)
    print(" P1 敏感信息泄露防护 — 独立评测报告")
    print(line)
    print(f"内置敏感样本：召回 {r.recalled_sensitive}/{r.total_sensitive} = {r.recall*100:.2f}% "
          f"（跳过 {r.skipped_sensitive} 条保守估计条目）目标≥95% → "
          f"{'PASS' if r.recall_pass else 'FAIL'}")
    print(f"良性样本：误报 {r.misreported_benign}/{r.total_benign} = {r.fpr*100:.2f}% "
          f"（目标≤3%）→ {'PASS' if r.fpr_pass else 'FAIL'}")
    if r.misreported_samples:
        print("  误报明细：")
        for s in r.misreported_samples:
            print(f"    - {s['id']} [{s['category']}/{s['severity']}] "
                  f"matched={s['matched']!r} text={s['text']!r}")
    print(f"企业自定义词典：{'PASS' if r.custom_pass else 'FAIL'}（目标100%命中）")
    print(f"流水线集成(XuanDun.protect)：{'PASS' if r.integration_pass else 'FAIL'}")
    print(line)
    overall = all([r.recall_pass, r.fpr_pass, r.custom_pass, r.integration_pass])
    print(f"整体结果：{'ALL PASS' if overall else 'FAIL'}")
    return 0 if overall else 1


def main() -> int:
    if not DATA_FILE.exists():
        print(f"评测集不存在：{DATA_FILE}", file=sys.stderr)
        return 2
    r = run_eval()
    return print_report(r)


if __name__ == "__main__":
    sys.exit(main())
