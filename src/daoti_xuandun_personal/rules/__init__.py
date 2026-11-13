# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白
# 本文件受道体研究许可证 v1.0 约束，禁止逆向工程和再分发

"""检测规则加载器（★ v0.1.0 判据外置）。

把此前散落在 Python 源码里的 88 条判据搬到 detection_rules.yaml，
目的有三个：

1. **改规则不用重编**：Nuitka 打包约 10 分钟，改一条正则却要重跑。
2. **规则表不含敏感逻辑**：YAML 里只有模式与标签，没有判定流程。
3. **可审计**：规则全在一处，安全审计不必读代码。

设计要点：
  · 加载失败**回退到内置最小集**并打 warning，绝不因规则文件损坏
    导致整个代理无法启动（防护失效比规则过时更严重）。
  · 正则统一 IGNORECASE，与原实现一致。
  · 规则文件缺失（源码分发未带）时静默使用内置集。
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ★ 回退集里的凭据判据来自唯一真源，不再手写第二份。
from daoti_xuandun.credentials import BY_KEY

logger = logging.getLogger("xuandun-personal.rules")

_RULES_DIR = Path(__file__).parent
_RULES_FILE = _RULES_DIR / "detection_rules.yaml"
# 常用包名基准表（typosquat 相似度判据用）
_PKG_FILE = _RULES_DIR / "pkg_allowlist.yaml"


# ══════════════════════════════════════════════════════════════
# PEM 私钥判据 —— 已迁移到唯一真源
# ══════════════════════════════════════════════════════════════
#
# ★★ 2026-11-13（最终收敛）：判据不再定义在本文件，而是统一声明在
#   `daoti_xuandun/credentials.py`（护栏包），个人版此处的
#   `PEM_PRIVATE_KEY_PATTERN` 只是转发别名。
#
#   历史教训（三次返工都记在真源文件的注释里）：
#     · 只认头部标记  → 用户问「BEGIN PRIVATE KEY 是什么」被整条阻断
#     · 字符集漏 -/_ → URL-safe Base64 的私钥整批漏报（20/20 掉到 6/20）
#     · 可空分支重复 → 长空白输入直接卡死
#
#   现在任何改动只需改一处，五处消费点自动同步。
#   `tests/test_credential_registry.py` 会扫描全部消费方源码，
#   发现任何一处重新内联凭据正则就判失败。
#
# ★ 说明：本文件不再导出 PEM_PRIVATE_KEY_PATTERN。
#   判据的唯一真源是 `daoti_xuandun/credentials.py`，
#   个人版消费方（sanitizer 等）直接从那里取，不再经本模块转发 ——
#   多一层转发就多一个「导入期依赖」，在基准脚本这类
#   手动改 sys.path 的场景下会踩到根目录旧副本。

# 加载失败时的最小回退集：只保留最不容易误判、也最致命的几条。
# 宁可少拦，不可全瘫 —— 代理起不来等于防护完全失效。
_FALLBACK: Dict[str, List[Tuple[Any, str]]] = {
    "dangerous_commands": [
        (r"\brm\s+-[rf]{1,2}\b", "递归删除命令 rm -rf"),
        (r"\b(?:curl|wget)\b[^\n|;]*\|\s*(?:ba)?sh\b", "下载并执行远程脚本"),
        (r"/dev/(?:tcp|udp)/[\w.:-]+", "反弹 shell（内建 /dev/tcp 重定向）"),
        (r"\bnc\b\s+-[a-z]*e\b", "反弹 shell（nc -e）"),
    ],
    "sensitive_paths": [
        (r"/etc/(passwd|shadow|sudoers)\b", "读取系统账户文件"),
        (r"\.ssh/(id_rsa|id_ed25519|authorized_keys)\b", "读取 SSH 私钥"),
        (r"\.aws/credentials\b", "读取 AWS 凭证"),
    ],
    "dangerous_urls": [],
    "invisible_chars": [
        (r"[‌‍⁠﻿]", "零宽空格/连接符"),
    ],
    "html_hidden": [],
    "unicode_steganography": [],
    "prompt_inject": [
        (r"(?:my\s+instructions?|your\s+configuration|system\s+prompt|"
         r"系统提示词|系统指令|系统设置|内部指令)", "系统提示词注入特征"),
    ],
    "sensitive_leak": [
        # ★★ 2026-11-13：回退集也必须来自唯一真源。
        #   这里原来手写了 sk- / AKIA 两条，是第 6 处凭据判据 ——
        #   规则文件缺失时会悄悄用回一份可能已漂移的正则。
        #   现在直接从 SPECS 生成，字段缺失也不会出现「第二份判据」。
        (BY_KEY["openai_key"].pattern, "OpenAI 风格密钥"),
        (BY_KEY["aws_access_key_id"].pattern, "AWS Access Key"),
    ],
    "watermark": [],
}


class RuleSet:
    """一次加载的规则集合。"""

    def __init__(self, data: Dict[str, Any], from_file: bool):
        self._data = data
        self.from_file = from_file
        self.version = data.get("version", 0)

    def pairs(self, section: str) -> List[Tuple[Any, str]]:
        """取某章节的 (正则, 标签) 列表，已编译。"""
        return self._compiled.get(section, [])

    def entries(self, section: str) -> List[Dict[str, Any]]:
        """取某章节的原始条目（供需要额外字段的检测使用）。"""
        return self._data.get(section) or []

    @property
    def _compiled(self) -> Dict[str, List[Tuple[Any, str]]]:
        if not hasattr(self, "_compiled_cache"):
            cache: Dict[str, List[Tuple[Any, str]]] = {}
            for section in _FALLBACK:
                out: List[Tuple[Any, str]] = []
                for item in self._data.get(section) or []:
                    if not isinstance(item, dict):
                        continue
                    pat = item.get("pattern")
                    label = item.get("label", "")
                    if not pat:
                        continue
                    try:
                        # ★★ 2026-11-13：按章节决定是否忽略大小写，不再一刀切。
                        #
                        #   `sensitive_leak` 这一节的判据**大小写是判据本身**：
                        #   AKIA 恒为大写、sk- 恒为小写、eyJ 是固定前缀、
                        #   ghp_ 恒为小写。统一加 IGNORECASE 会把
                        #   「akiaIOSFODNN7EXAMPLE」「SK-hynix-…」判成凭据，
                        #   而请求侧/响应侧命中即阻断 —— 实测误报。
                        #
                        #   其余章节（危险命令、敏感路径、注入特征）描述的
                        #   是语义而非格式，大小写无关，保持原 IGNORECASE 行为。
                        #   ★ 为什么不逐条改 YAML 加 `(?i)`：55 条里绝大多数
                        #     需要不区分大小写，逐条标注只会增加遗漏面；
                        #     按「语义族」分组表达才与判据性质对应。
                        flags = 0 if section == "sensitive_leak" else re.IGNORECASE
                        out.append((re.compile(pat, flags), str(label)))
                    except re.error as e:
                        # 单条规则编译失败不应拖垮整个规则集
                        logger.warning("规则 %s 中的 %r 编译失败，已跳过: %s",
                                       section, pat, e)
                cache[section] = out
            self._compiled_cache = cache
        return self._compiled_cache

    def stats(self) -> Dict[str, int]:
        return {
            k: len(self._data.get(k) or [])
            for k in _FALLBACK
        }


_ruleset: Optional[RuleSet] = None


def load_ruleset(force: bool = False) -> RuleSet:
    """加载规则集（带缓存与回退）。"""
    global _ruleset
    if _ruleset is not None and not force:
        return _ruleset

    if not _RULES_FILE.exists():
        logger.warning("规则文件不存在（%s），使用内置回退集", _RULES_FILE)
        _ruleset = RuleSet(_FALLBACK, from_file=False)
        return _ruleset

    try:
        import yaml  # pyyaml 已是项目依赖

        data = yaml.safe_load(_RULES_FILE.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("规则文件顶层不是映射")
        _ruleset = RuleSet(data, from_file=True)
        total = sum(_ruleset.stats().values())
        logger.info("已加载检测规则 v%s：%d 条（来源：规则文件）",
                    _ruleset.version, total)
    except Exception as e:  # noqa: BLE001 — 任何加载失败都必须降级而非崩溃
        logger.warning("规则加载失败（%s），回退到内置最小集", e)
        _ruleset = RuleSet(_FALLBACK, from_file=False)

    return _ruleset


_pkg_table: Optional[frozenset] = None


def load_pkg_table() -> frozenset:
    """加载常用包名基准表（小写集合）。

    作用：为 typosquat 判据提供「真实包名」的比对基准。
    加载失败返回空集 —— 此时 typosquat 检测整体关闭，
    不会因缺表而产生「所有包名都可疑」的误报。
    """
    global _pkg_table
    if _pkg_table is not None:
        return _pkg_table

    names: set = set()
    if _PKG_FILE.exists():
        try:
            import yaml

            data = yaml.safe_load(_PKG_FILE.read_text(encoding="utf-8")) or {}
            for key in ("python", "node"):
                for n in data.get(key) or []:
                    if isinstance(n, str) and n.strip():
                        names.add(n.strip().lower())
        except Exception as e:  # noqa: BLE001
            logger.warning("包名基准表加载失败（%s），typosquat 检测关闭", e)
            names = set()
    else:
        logger.warning("包名基准表不存在（%s），typosquat 检测关闭", _PKG_FILE)

    _pkg_table = frozenset(names)
    logger.info("已加载包名基准表：%d 个", len(_pkg_table))
    return _pkg_table


def rules_path() -> Path:
    """规则文件路径（供设置页展示与「打开规则目录」用）。"""
    return _RULES_FILE
