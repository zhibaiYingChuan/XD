# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白
# 本文件受道体研究许可证 v1.0 约束，禁止逆向工程和再分发
# 详见 LICENSE 文件

"""模拟测试引擎 — 使用内置攻击样本库测试玄盾的防护能力。

三种测试模式：
  - quick:  快速验证，每类取代表性样本，约15秒完成
  - full:   全面测试，全部200+攻击样本 + 良性样本，生成完整报告
  - custom: 自定义测试，运维人员手动输入文本
"""

import time
import uuid
from typing import List, Optional

from attack_samples import build_all_attack_categories, get_benign_samples

# 攻击分类关键词映射（与 engine_flask 保持同步）
_ATTACK_CATEGORY_KEYWORDS = {
    "direct_prompt_injection": [
        "忽略之前", "忽略所有", "忘记指令", "忘掉", "override",
        "disregard", "ignore all", "ignored", "new instruction",
        "你是一个", "你现在是", "扮演", "假装", "pretend",
        "acting as", "you are now", "从今天起", "作为",
    ],
    "indirect_prompt_injection": [
        "邮件内容说", "网页内容包含", "文档中提到",
        "the email says", "the page says", "injected",
        "根据附件", "根据收到的消息",
    ],
    "jailbreak": [
        "DAN", "jailbreak", "越狱", "已解锁", "unlocked",
        "mode", "filters", "bypass", "bypassing",
        "不受限制", "unrestricted", "没有限制", "no restrictions",
        "filter bypass", "解放", "自由模式", "不受约束",
    ],
    "encoding_obfuscation": [
        "base64", "rot13", "hex", "编码", "encoded",
        "obfuscated", "混淆", "unicode", "escape",
        "反向", "倒序", "reverse",
    ],
    "agent_attack": [
        "执行命令", "运行", "execute", "shell", "terminal",
        "system", "cmd", "powershell", "sudo", "bash",
        "curl", "wget", "http请求", "访问网站", "访问链接",
        "delete file", "写入文件", "write to", "read file",
        "入侵", "攻击", "exploit",
    ],
    "data_leakage": [
        "告诉我密码", "泄露", "泄漏", "leak", "密码是",
        "credit card", "ssn", "social security", "token",
        "api key", "secret key", "私钥", "password",
        "database credentials", "connection string",
    ],
}


def _classify_attack_category(text: str) -> str:
    """基于关键词匹配对输入文本进行攻击分类。"""
    text_lower = text.lower()
    for category, keywords in _ATTACK_CATEGORY_KEYWORDS.items():
        for kw in keywords:
            if kw.lower() in text_lower:
                return category
    return "other"


class SimulationEngine:
    """模拟测试引擎：调用玄盾检测引擎批量测试攻击样本。"""

    def __init__(self, shield):
        self.shield = shield
        self._categories = build_all_attack_categories()
        self._benign = get_benign_samples()

    def run(self, mode: str = "quick",
            categories: Optional[List[str]] = None,
            custom_texts: Optional[List[str]] = None) -> dict:
        """运行模拟测试。

        Args:
            mode: "quick" | "full" | "custom"
            categories: 指定测试的类别（仅 full 模式有效）
            custom_texts: 自定义测试文本（仅 custom 模式有效）

        Returns:
            测试报告字典
        """
        t0 = time.perf_counter()

        if mode == "custom":
            results = self._run_custom(custom_texts or [])
        elif mode == "full":
            results = self._run_full(categories)
        else:
            results = self._run_quick()

        elapsed = time.perf_counter() - t0

        report = self._build_report(results, mode, elapsed)
        return report

    def _run_quick(self) -> List[dict]:
        """快速验证：每类取前2个攻击样本 + 5个良性样本。"""
        results = []
        session = f"sim_quick_{uuid.uuid4().hex[:8]}"

        for cat in self._categories:
            for text, expected in cat.samples[:2]:
                result = self._test_one(text, expected, cat.key, cat.name, session)
                results.append(result)

        for text, expected in self._benign[:5]:
            result = self._test_one(text, expected, "benign", "良性样本", session)
            results.append(result)

        return results

    def _run_full(self, categories: Optional[List[str]] = None) -> List[dict]:
        """全面测试：全部攻击样本 + 全部良性样本。"""
        results = []
        session = f"sim_full_{uuid.uuid4().hex[:8]}"

        for cat in self._categories:
            if categories and cat.key not in categories:
                continue
            for text, expected in cat.samples:
                result = self._test_one(text, expected, cat.key, cat.name, session)
                results.append(result)

        for text, expected in self._benign:
            result = self._test_one(text, expected, "benign", "良性样本", session)
            results.append(result)

        return results

    def _run_custom(self, texts: List[str]) -> List[dict]:
        """自定义测试：用户提供的文本，无法判定期望标签。"""
        results = []
        session = f"sim_custom_{uuid.uuid4().hex[:8]}"

        for text in texts:
            if not text.strip():
                continue
            result = self._test_one(text, "unknown", "custom", "自定义", session)
            results.append(result)

        return results

    def _test_one(self, text: str, expected: str,
                  category_key: str, category_name: str,
                  session: str) -> dict:
        """测试单个样本。"""
        t0 = time.perf_counter()
        try:
            result = self.shield.protect(text, session_id=session)
            elapsed_ms = (time.perf_counter() - t0) * 1000
            allowed = result.allowed
        except Exception as e:
            elapsed_ms = (time.perf_counter() - t0) * 1000
            allowed = False

        actual = "allowed" if allowed else "blocked"

        if expected == "attack":
            correct = not allowed
        elif expected == "benign":
            correct = allowed
        else:
            correct = None

        return {
            "category_key": category_key,
            "category_name": category_name,
            "text_preview": text[:80] + ("..." if len(text) > 80 else ""),
            "expected": expected,
            "actual": actual,
            "allowed": allowed,
            "correct": correct,
            "latency_ms": round(elapsed_ms, 2),
            "trust_level": result.trust_level.value if hasattr(result, 'trust_level') and result.trust_level else None,
            "domain_distance": round(result.domain_distance, 4) if hasattr(result, 'domain_distance') and result.domain_distance else None,
            "attack_category": _classify_attack_category(text),
        }

    def _build_report(self, results: List[dict], mode: str, elapsed: float) -> dict:
        """构建测试报告。"""
        total = len(results)
        attack_total = sum(1 for r in results if r["expected"] == "attack")
        attack_blocked = sum(1 for r in results if r["expected"] == "attack" and not r["allowed"])
        benign_total = sum(1 for r in results if r["expected"] == "benign")
        benign_blocked = sum(1 for r in results if r["expected"] == "benign" and not r["allowed"])
        attack_passed = sum(1 for r in results if r["expected"] == "attack" and r["allowed"])

        block_rate = round(attack_blocked / max(1, attack_total), 4)
        false_positive_rate = round(benign_blocked / max(1, benign_total), 4)
        miss_rate = round(attack_passed / max(1, attack_total), 4)

        category_stats = {}
        for r in results:
            if r["expected"] not in ("attack", "benign"):
                continue
            key = r["category_key"]
            if key not in category_stats:
                category_stats[key] = {
                    "name": r["category_name"],
                    "total": 0,
                    "blocked": 0,
                    "passed": 0,
                }
            category_stats[key]["total"] += 1
            if not r["allowed"]:
                category_stats[key]["blocked"] += 1
            else:
                category_stats[key]["passed"] += 1

        for key in category_stats:
            s = category_stats[key]
            s["block_rate"] = round(s["blocked"] / max(1, s["total"]), 4)

        avg_latency = sum(r["latency_ms"] for r in results) / max(1, total)

        return {
            "mode": mode,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "elapsed_seconds": round(elapsed, 2),
            "total_samples": total,
            "attack_total": attack_total,
            "attack_blocked": attack_blocked,
            "benign_total": benign_total,
            "benign_blocked": benign_blocked,
            "block_rate": block_rate,
            "false_positive_rate": false_positive_rate,
            "miss_rate": miss_rate,
            "accuracy": round((attack_blocked + (benign_total - benign_blocked)) / max(1, attack_total + benign_total), 4),
            "avg_latency_ms": round(avg_latency, 2),
            "category_stats": category_stats,
            "details": results[-50:],
        }
