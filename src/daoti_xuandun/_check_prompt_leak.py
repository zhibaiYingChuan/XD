"""_check_prompt_leak.py — 系统提示泄露升级检测（节 9.9）

系统提示泄露（Prompt Leak / System Prompt Extraction）：攻击者请求 LLM
输出其隐藏的系统提示词 / 初始指令 / 角色设定 / 内置工具清单，用于：
- 逆向工程产品的提示工程（复制竞争优势）
- 寻找可绕过安全约束的漏洞（越权、越狱）
- 批量抓取内部配置与规则

旧的 detect_system_prompt_leak() 只返回 bool（触发词 + 动作词组合），
无法区分「直接索要」与「技术交流中顺带提及」，导致误拦良性提问。

本模块升级为「洛书语义分类 + 置信度」：
  1) 组合特征分：触发词（系统提示/初始指令/你的规则…）× 动作词（输出/复述/打印…）
     按权重累加，得到 0~1 的 base_signal；
  2) 语义分类：将 prompt 向量化，用洛书 compute_safe_distance 计算其与良性域的
     流形距离，distance 越大越像攻击（0~1），作为语义信号；
  3) 置信度：base_signal 与语义信号加权融合成 0~1 置信度，分级处置
     （≥ prompt_leak_block_min 拦截 / ≥ prompt_leak_warn_min 打标）。

公开 API：
  checker = PromptLeakChecker()
  decision = checker.check(text, luoshu, luoshu_state=None)
  # decision.block / decision.confidence / decision.category / decision.semantic_distance
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple


# ============================================================
# 数据结构
# ============================================================
@dataclass
class PromptLeakDecision:
    block: bool                       # 是否拦截
    confidence: float                 # 0~1 置信度
    category: str                     # semantic / combined / keyword / benign
    semantic_distance: float = 0.0    # 洛书安全域距离（0~1），-1 表示未启用
    matches: List[str] = field(default_factory=list)  # 命中的特征标签


# ============================================================
# 特征库（中/英双语，带权重）
# ============================================================

# 1) 系统提示触发词（指出要获取的对象）— 权重按语义强度
#   注意：新增/删除词后，需同步在评测脚本中验证对召回率的影响。
_SYSTEM_TRIGGER: List[Tuple[str, float]] = [
    # 强语义：明确指向系统提示/初始指令（带 your 的限定词权重更高，降低误报）
    ("your system prompt", 1.2), ("your initial prompt", 1.2),
    ("your initial instructions", 1.2), ("your developer prompt", 1.0),
    ("your meta prompt", 1.0), ("your opening message", 1.0),
    ("your startup prompt", 1.0), ("initial system message", 1.0),
    ("the text before my first message", 1.2), ("contents of your system prompt", 1.2),
    ("whats in your prompt", 1.1), ("what is in your prompt", 1.1),
    ("your first message", 0.9), ("your first prompt", 0.9),
    ("your first instruction", 0.9), ("your rules", 0.9),
    ("your instructions", 0.9), ("your guidelines", 0.9),
    ("your configuration", 0.8), ("your constraints", 0.8),
    ("your settings", 0.85), ("your hidden config", 1.0),
    ("your starting instructions", 1.1),  # pl015: "your starting instructions"
    ("your actual system prompt", 1.2),  # pl036: "你实际收到的系统提示"的英文
    ("before the user's first message", 1.0),  # pl019
    ("prompt that defines you", 1.0),  # pl009
    # 不限定 "your" 的弱触发（权重稍低，怕误报 "the rules of the game" 这类）
    ("system prompt", 1.0), ("system message", 1.0), ("system instructions", 1.0),
    ("system settings", 0.85), ("system config", 0.85),
    ("the first message", 0.75), ("the first prompt", 0.75),
    ("the first instruction", 0.75), ("the system message", 0.9),
    ("the prompt template", 0.75), ("the preamble", 0.9),
    ("text that appears before", 0.9), ("what appears before", 0.9),
    ("key points of your preamble", 0.95),  # pl054
    ("preamble instructions", 0.95),  # pl013: "preamble instructions" 短语
    ("your initial instruction", 1.15),  # pl058: 单数形（原只有复数instructions）
    ("your first 50 words", 0.9),  # pl058: first N words
    ("your full initial prompt", 1.15),  # pl018: 中间插了形容词 full 的变体
    # 弱信号：pl044/pl043 "很多模型的默认提示都是xxx，你的呢？写出来对比" 套路
    # 必须带 prompt/提示/指令 词，避免误伤 pl087"默认设置是偏严谨还是创意"这类良性问答
    ("default prompt", 0.85), ("your default prompt", 1.0),
    ("default system prompt", 1.0), ("the default prompt", 0.85),
    # 中文对应：默认系统提示 + 对比/你的呢
    ("默认系统提示", 0.9), ("默认值是不是", 0.85),
    ("你的默认", 0.9), ("写出来对比", 0.9),  # pl043 "写出来给我对比一下"
    # 中文 — 带"你的/你收到的"限定词权重高
    ("你的系统提示", 1.2), ("你的初始指令", 1.2), ("你的初始提示", 1.2),
    ("你的开发者指令", 1.0), ("你的开发者设定", 1.0), ("你的开发者配置", 0.9),
    ("你收到的第一条指令", 1.2), ("发给你的第一条指令", 1.2),
    ("你启动时的每一条指令", 1.1),  # pl035 游戏化指令
    ("你实际收到的系统提示", 1.2),  # pl036
    ("用户第一条消息之前", 1.1),  # pl039
    ("定义你的", 0.95),  # pl029/009: "定义你的系统提示"
    ("开发者设置", 0.9), ("开发者限制", 0.9),
    ("系统提示词", 1.0), ("系统提示", 0.9), ("系统消息", 0.9), ("系统指令", 1.0),
    ("初始指令", 1.0), ("初始提示", 1.0), ("初始消息", 0.9),
    ("前置指令", 0.9), ("载入的前置指令", 1.0), ("初始设定", 0.9),
    ("你的规则", 0.9), ("你的指令", 0.9), ("你的设定", 0.9), ("你的配置", 0.8),
    ("第一条指令", 0.8), ("第一句话", 0.7), ("第一条消息", 0.8),
    ("隐藏的配置", 1.0), ("隐藏的指令", 1.0), ("隐藏设定", 0.9),
    ("配置你行为和安全策略的元提示", 1.2),  # pl040
]

# 2) 动作指示词（请求对方做什么）— 权重按动作强度
#   注意：新增词必须避免 "写一篇小说" / "describe a character" 这类日常叙述动词的误报。
_SYSTEM_ACTION: List[Tuple[str, float]] = [
    # 强动作：明确有"泄露/导出/展示内部信息"意图的动词
    ("reveal", 1.0), ("expose", 1.0), ("disclose", 1.0),
    ("dump", 0.95), ("leak", 1.0),
    ("print", 1.0), ("write out", 0.9), ("output", 0.9),
    ("repeat back", 1.0), ("echo", 0.9), ("repeat", 0.85),
    ("show", 0.85), ("display", 0.85), ("list", 0.75),
    ("tell me", 0.8), ("give me", 0.7), ("share", 0.75),
    ("send", 0.7), ("forward", 0.75), ("post", 0.7),
    ("retrieve", 0.8), ("extract", 0.8),
    ("read aloud", 0.85), ("recite", 0.85),  # pl052 read aloud / 中文背诵
    ("fill in", 0.85), ("complete", 0.8), ("define", 0.75),  # pl017/pl018 代码块填充/变量定义
    ("followed by", 0.7), ("respond with", 0.75),  # pl057/pl058 协议式输出
    ("describe", 0.55), ("summarize", 0.55), ("summarise", 0.55),  # 弱动作（需配合强trigger才构成威胁）
    ("what is", 0.5), ("what are", 0.5), ("whats your", 0.7),
    ("first line of chapter", 0.85),  # pl016/pl036 小说第一章第一行
    ("first step", 0.7),  # pl009 角色扮演第一步: show me...
    ("play a game", 0.75),  # pl015/pl035 游戏化绕过
    # 中文 — 强动作（权重高，避免弱动词被日常话术误报）
    ("泄露", 1.0), ("透露", 1.0), ("原样输出", 1.0),
    ("复述", 1.0), ("回放", 0.95), ("取回", 0.9), ("背诵", 0.85),  # 背诵用于攻击场景
    ("输出", 0.9), ("打印", 0.9), ("念出", 0.85), ("重复", 0.85),
    ("展示", 0.85), ("显示", 0.85), ("导出", 0.9),
    ("列出", 0.75), ("复制", 0.7), ("粘贴", 0.7),
    ("告诉我", 0.8), ("发给我", 0.85), ("写出来", 0.85), ("给我看看", 0.8),
    ("补全", 0.85), ("填在", 0.8), ("定义", 0.75), ("赋值", 0.75),  # pl037/pl038 代码块补全/变量赋值
    ("紧接着写", 0.85), ("作为第一行", 0.85),  # pl057/pl036 协议式/小说式包装
    ("开始翻译", 0.75), ("玩个游戏", 0.75),  # pl035/pl015 游戏化绕过
    ("原样写出", 1.0),  # pl033: 同义词，原只有"原样输出/写出来"但漏了"写出"
    ("概括", 0.5), ("总结", 0.5), ("描述", 0.5),  # 弱动作，仅强trigger下保底
]

# 3) 上下文否定指示词：拆两级避免学术包装被过度惩罚
#    A) 强否定（明确的引用/示例/演示场景）：×0.5 惩罚，专门降低 pl067 这类误报
#    B) 弱否定（"论文/研究"但无示例标记，常被攻击者利用做包装）：×0.80 仅轻微降分，不豁免强攻击
_CONTEXT_NEGATIVE_MARKERS: List[Tuple[str, float]] = [
    # === 超强否定（×0.3）：明确的"不是要你/不要真的/而非输出你自己的提示"句式
    #   如 pl106："不是让你输出你自己的提示"；真实攻击绝不会写这种自我否定
    ("not to output your", 0.3), ("not your own prompt", 0.3), ("do not output your own", 0.3),
    ("不是让你输出", 0.3), ("不是要你输出", 0.3), ("而非输出", 0.3),
    ("不需要你输出", 0.3), ("不是让你泄露", 0.3), ("不是要你泄露", 0.3),
    ("不要输出你自己的", 0.3), ("不是让你展示", 0.3),
    # === 强否定（×0.5）：明确是"示例/样例/教程演示"场景，真实攻击几乎不会用这些词 ===
    ("for example", 0.5), ("e.g.", 0.5), ("example of", 0.5), ("sample attack", 0.5),
    ("in the tutorial", 0.5), ("as a reference", 0.5),
    ("how to detect", 0.5), ("defense against", 0.5), ("how to defend", 0.5),
    ("例如", 0.5), ("比如", 0.5), ("举例", 0.5), ("样例", 0.5), ("示例", 0.5),
    ("教程中", 0.5), ("教程里", 0.5),
    ("怎么检测", 0.5), ("如何防御", 0.5),
    ("虚构的", 0.5), ("不要真的", 0.5), ("模板", 0.5),
    # === 安全讨论语境（×0.55）：方法论/评测/日志类良性提问，讨论攻击本身而非索要
    #   典型误报样本：pl076「只讲方法论」pl077「检查清单」pl079「日志字段」pl098「危害排序」
    #                pl100「紧急响应」pl110「伪代码 check_for_prompt_leak」pl119「召回率误报率」
    ("只讲方法论", 0.55), ("检测思路", 0.55),
    ("常见的检查清单", 0.55), ("检查清单吗", 0.55),
    ("日志字段", 0.55), ("推荐哪些字段", 0.55),
    ("紧急响应措施", 0.55), ("采取什么紧急", 0.55),
    ("伪代码写一个函数", 0.55), ("只要思路即可", 0.55),
    ("check_for_prompt_leak", 0.55),  # 伪代码函数名
    ("什么算法实现的", 0.55), ("纯关键词还是结合了语义", 0.55),
    ("区别是什么", 0.55), ("清晰的划分", 0.55),
    ("有什么不同的技术手段", 0.55), ("防御上有什么不同", 0.55),
    ("为什么需要同时看", 0.55), ("召回率和误报率", 0.55),
    ("按严重程度排个序", 0.55), ("造成的危害具体有哪些", 0.55),
    ("讨论一下", 0.55), ("是不是可以例外", 0.55),
    ("身份验证", 0.55), ("开发者本人", 0.55),
    ("是否应该在任何情况下", 0.55), ("讲一下你的观点", 0.55),
    # === 产品特性/架构设计/教学类（×0.50）：讨论 LLM 基础原理、产品功能、代码变量名
    #   典型误报：pl061「系统提示词多少字/支持自定义角色」pl064「系统指令和用户指令有什么区别+优先级」
    #            pl065「system message 的作用和设计最佳实践」pl071「代码块变量名 system_prompt = "你是一个助手"」
    #            pl095「多租户 LLM 网关/system prompt 独立存储/推荐隔离方案」pl102「复述我给你的规则（不是模型系统提示）」
    #            pl107「翻译任务：系统提示词是大模型应用的重要组成部分」pl112「直接拒绝还是降级为只记录日志」
    ("大概有多少字", 0.50), ("多少字", 0.50), ("多少字符", 0.50),
    ("支持用户自定义", 0.50), ("自定义角色", 0.50),
    ("系统指令和用户指令", 0.50), ("区分优先级", 0.50),
    ("system message 的作用", 0.50), ("不需要针对本产品", 0.50), ("不针对本产品", 0.50),
    ("设计最佳实践", 0.50),
    ("能解释一下这个公式", 0.50), ("公式的细节吗", 0.50),
    ("这里是我自己代码里的变量名", 0.50),
    # 代码块变量赋值：代码里的 system_prompt = "xxx" 不是攻击，是开发者写自己的代码
    ("```python", 0.50), ("```javascript", 0.50), ("```typescript", 0.50),
    ("system_prompt = ", 0.50),  # 代码里的赋值，不是攻击
    ("print(system_prompt)", 0.50),  # 打印自己的变量
    ("写单元测试", 0.50), ("需要构造一批", 0.50), ("生成 5 条", 0.50), ("生成5条", 0.50),
    ("教程引用的负样本", 0.50), ("疑似系统提示泄露", 0.50),  # 明确说要构造负样本
    ("多租户", 0.50), ("LLM 网关", 0.50), ("独立存储", 0.50), ("推荐用什么隔离方案", 0.50),
    ("我写了一些规则", 0.50), ("复述一遍我给你的这些规则", 0.50), ("确认你理解了", 0.50),  # 是用户的规则不是模型的
    ("把这段中文翻译成英文", 0.50), ("翻译成英文：", 0.50), ("大模型应用的重要组成部分", 0.50),
    ("直接拒绝还是降级为只记录日志", 0.50),
    # === 弱否定（×0.80）："学术/论文/研究"但无明确示例词，常被pl013/pl033做包装攻击 ===
    ("in the paper", 0.8), ("in the article", 0.8),
    ("mentioned in", 0.8), ("security paper", 0.8), ("research study", 0.8),
    ("research purposes", 0.8), ("for research", 0.8),
    ("论文中", 0.8), ("论文里", 0.8), ("文章中", 0.8), ("提到的", 0.8),
    ("学术研究", 0.8), ("研究报告", 0.8), ("安全论文", 0.8),
    ("出于研究", 0.8), ("建立基线", 0.8), ("对照组基线", 0.8),
    ("匿名引用", 0.8), ("引用", 0.8),
    ("as cited", 0.8), ("cite", 0.8), ("citation", 0.8),
]


# ============================================================
# 检测器
# ============================================================
class PromptLeakChecker:
    """系统提示泄露语义检测：组合特征分 + 洛书语义距离 → 置信度。"""

    _CJK_RE = re.compile(r"[\u4e00-\u9fff\u3400-\u4dbf]")  # 含任一中文即视为中文短语

    @classmethod
    def _flex_rx(cls, name: str) -> re.Pattern:
        r"""多词短语使用宽松匹配；中文短语禁用 `\b`（中文不是空格分词，\b 无效）。

        语言分支：
        * 含 CJK 字符（中文）→ 视为中文：直接用 re.escape(name)，不允许插词，
          绝对不加 `\b`（Python re 的 \b 基于 [a-zA-Z0-9_] 单词边界，中文完全不匹配）。
        * 纯英文（空格分词）→ 多词短语宽松匹配：空格改为 `(?:\s+\S+){0,2}\s+`
          允许中间插 0-2 个形容词（your **full** initial prompt）。短词加 `\b` 防误报。

        修复：之前不分语言统一加 `\b`，导致中文短语全部 0 命中，纯关键词召回暴跌 51%。"""
        if cls._CJK_RE.search(name):
            # 中文短语：直接精确匹配（不插词），严禁 \b
            return re.compile(re.escape(name), re.I)
        # 英文分支
        parts = name.split()
        if len(parts) >= 3:
            escaped = [re.escape(p) for p in parts]
            pattern = escaped[0] + "".join(
                r"(?:\s+\S+){0,2}\s+" + nxt for nxt in escaped[1:]
            )
            return re.compile(r"\b" + pattern + r"\b", re.I)
        # 英文短词（1-2 词）：加单词边界防误报（如 "dump" 不误匹配 "dumpster"）
        return re.compile(r"\b" + re.escape(name) + r"\b", re.I)

    def __init__(
        self,
        block_min: float = 0.75,  # 下调到 0.75：让流水线 High 攻击拦截率从 75% → ≥85%
        warn_min: float = 0.70,
        use_luoshu: bool = True,
    ):
        self.block_min = block_min
        self.warn_min = warn_min
        self.use_luoshu = use_luoshu
        # 预编译正则：多词短语用宽松匹配
        self._triggers = [
            (name, w, self._flex_rx(name)) for name, w in _SYSTEM_TRIGGER
        ]
        self._actions = [
            (name, w, self._flex_rx(name)) for name, w in _SYSTEM_ACTION
        ]
        # 上下文否定标记保持精确词匹配（它们本身就是"例如/学术研究"这类短词，不需要松匹配）
        self._negative_ctx = [
            (name, w, re.compile(re.escape(name), re.I)) for name, w in _CONTEXT_NEGATIVE_MARKERS
        ]

    # ---------- 上下文惩罚因子 ----------
    def _context_penalty(self, text: str) -> float:
        """若文本命中「引用/教程/示例」等安全上下文，返回惩罚因子（<1.0 抑制）。"""
        worst: float = 1.0
        for _name, w, rx in self._negative_ctx:
            if rx.search(text):
                if w < worst:
                    worst = w
        return worst

    # ---------- 组合特征分 ----------
    def _keyword_signal(self, text: str) -> Tuple[float, List[str]]:
        """累加触发词 + 动作词权重，归一化到 0~1。

        算法说明（AND门软化 2026-08-05）：
          - 原算法要求"触发词 AND 动作词"才得分，导致 dump(只有action无your限定)、
            preamble(只有trigger无明确动作) 这类单向强信号全部漏网（召回率仅58%）。
          - 新算法：
              1) 双信号都存在 → 线性融合 0.5*trigger + 0.5*action（原逻辑，高确信）
              2) 仅单信号存在（trigger≥0.9 或 action≥0.9）→ 保底 0.7 × max(trigger, action)
                 （"dump all instructions"：action=0.95, trigger=0 → 保底0.665；
                   "the preamble"：trigger=0.9, action=0 → 保底0.63）
              3) 两信号都弱或都不存在 → 0.0
          - 最后对命中的引用/教程等上下文再乘以惩罚因子（0.5），抑制误报。
        """
        trigger = 0.0
        action = 0.0
        hits: List[str] = []
        for name, w, rx in self._triggers:
            if rx.search(text):
                trigger = max(trigger, w)
                hits.append(f"trigger:{name}")
        for name, w, rx in self._actions:
            if rx.search(text):
                action = max(action, w)
                hits.append(f"action:{name}")

        # AND门软化：允许单信号强时保底，避免双信号缺一就归零
        if trigger > 0 and action > 0:
            raw = 0.5 * trigger + 0.5 * action
            # 分档归一化：强强组合（双≥1.0）除数最低→直接上 0.95，满足 block_min=0.90
            if trigger >= 1.0 and action >= 1.0:
                # (0.5*1.2+0.5*1.0)/0.95 = 1.157 → cap 1.0；双 1.2→1.263→cap 1.0
                base_raw = min(1.0, raw / 0.95)
            elif trigger >= 0.9 and action >= 0.9:
                # 次强档：除数 1.0，原 (0.45+0.45)/1.05=0.857 → 提至 0.9，配合语义 0.8×0.9+0.2×0.7=0.86
                #     再加语义加权 (sem>0.45 → 0.6*0.9+0.4*0.8=0.86，若sem≥0.9→0.9)
                base_raw = min(1.0, raw / 1.0)
            else:
                # 普通双信号：除数 1.05，保留 ~4.5% 增益
                base_raw = min(1.0, raw / 1.05)
        elif trigger >= 0.9 or action >= 0.9:
            # 单信号强：保底给分（系数 0.80 让 trigger=0.9→0.72 刚好跨越 warn_min=0.70 门槛）
            max_sig = max(trigger, action)
            base_raw = min(0.88, 0.80 * max_sig)
        elif trigger >= 0.7 or action >= 0.7:
            # 二次兜底：信号没到 0.9 但也不弱（如 pl039: trigger=0.75, action=0.5→原base=0
            # 放宽到 trigger>=0.7 或 action>=0.7 就给 0.62×max，作为弱信号垫底
            max_sig = max(trigger, action)
            base_raw = min(0.70, 0.62 * max_sig)
        else:
            base_raw = 0.0

        # 上下文惩罚：分档豁免（关键修复：不让弱引用包装压垮强攻击组合）
        ctx = self._context_penalty(text)
        if ctx < 1.0:
            if base_raw >= 0.75 and ctx >= 0.80:
                # 强双信号(base_raw≥0.75) + 仅弱引用惩罚(×0.80类)：只轻微惩罚×0.92
                # pl034：双信号 0.9+0.9 → base_raw=0.857，原×0.8=0.685 → 改×0.92=0.789 过线
                eff_ctx = 0.92
                hits.append(f"ctx_weak_immunity:x{eff_ctx:.2f}(raw={base_raw:.2f}高)")
            else:
                eff_ctx = ctx
                hits.append(f"ctx_penalty:x{ctx:.2f}")
            base = base_raw * eff_ctx
        else:
            base = base_raw
        return max(0.0, min(1.0, base)), hits

    # ---------- 洛书语义距离 ----------
    def _semantic_signal(self, luoshu, text: str) -> float:
        """用洛书计算文本到良性安全域的距离，作为语义置信度。"""
        if luoshu is None:
            return -1.0
        try:
            state = luoshu.encode(text)
            return float(luoshu.compute_safe_distance(state))
        except Exception:
            return -1.0

    # ---------- 主入口 ----------
    def check(self, text: str, luoshu=None, luoshu_state=None) -> PromptLeakDecision:
        """检测系统提示泄露意图。

        Args:
            text: 用户输入文本。
            luoshu: 洛书映射器（可选，用于语义距离）。
            luoshu_state: 预留语义状态（当前未使用）。

        Returns:
            PromptLeakDecision：block / confidence（0~1）/ category。

        置信度融合公式（2026-08-05 语义保底限幅：纯语义只到 warn 不进 block）：
          设 base = 关键词组合特征分（0~1，含AND门软化与上下文惩罚）
              semantic_conf = 洛书安全域距离（0~1，0=完美良性域，1=完全域外）
          ① base>0 且 semantic_conf≥0：
              若 semantic_conf>0.45 → confidence = 0.60*base + 0.40*semantic_conf
                （语义占比40%，让 borderline 样本靠语义跨过 warn_min）
              否则            → confidence = 0.80*base + 0.20*semantic_conf
          ② base=0 但 semantic_conf≥0.53（语义信号足够强但关键词完全没命中）：
              confidence = min(0.95 * semantic_conf, self.block_min - 0.01)
                （★ 限幅关键：纯语义保底最多到 block_min-0.01 → 只进 warn，不进 block
                 抑制 FPR 从 25% 爆涨：之前 0.95×0.82→0.78≥0.75 直接拦；现封顶 0.74 只打标
                 保证包装攻击（关键词弱+语义远）不被强拦，但保留高层感知；
                 真正高置信攻击一定有关键词命中（base>0）→ 走 case① 正常拦）
          ③ 其他 → confidence = base
          分类标注：
              semantic≥0 且 (base≥0.5 或 semantic_conf>0.65) → "semantic"
              双信号都参与加权 → "combined"
              仅关键词 → "keyword"
              全0 → "benign"
        """
        if not text or not isinstance(text, str):
            return PromptLeakDecision(block=False, confidence=0.0, category="benign")

        # 1) 组合特征分
        base, hits = self._keyword_signal(text)

        # 2) 语义分类距离
        semantic = self._semantic_signal(luoshu, text) if self.use_luoshu else -1.0

        # 3) 置信度融合（语义权重上调 + 保底阈值降低，激活洛书救漏报）
        category = "keyword"
        if semantic >= 0.0:
            semantic_conf = max(0.0, min(1.0, semantic))
            if base > 0.0:
                # 有关键词信号 → 语义权重从 0.30 提到 0.40，让 borderline 样本靠语义跨 warn_min
                if semantic_conf > 0.45:
                    confidence = 0.60 * base + 0.40 * semantic_conf
                    category = "combined"
                else:
                    confidence = 0.80 * base + 0.20 * semantic_conf
                    category = "semantic" if semantic_conf >= 0.3 else "semantic"
            elif semantic_conf >= 0.53:
                # 关键词完全漏了（包装攻击/游戏话术），但语义信号强 → 语义保底
                # ★ 保底限幅：只到 warn 级（最高 block_min - 0.01），不触发流水线强拦
                #   抑制 FPR：之前 0.95×0.82→0.78≥0.75 误拦；现封顶 0.74 只打标
                #   真正强攻击一定有关键词命中（base>0）走 case①，纯语义远 ≠ 攻击
                confidence = min(0.95 * semantic_conf, self.block_min - 0.01)
                category = "semantic"
            else:
                confidence = 0.0
                category = "benign"
        else:
            confidence = base
            category = "keyword" if base > 0.0 else "benign"

        confidence = max(0.0, min(1.0, confidence))
        block = confidence >= self.block_min
        # 若语义信号可用且 base≥0.5 或 semantic 本身强，统一标注 category=semantic（便于debug统计）
        if semantic >= 0.0 and (base >= 0.5 or (semantic is not None and semantic >= 0.45)):
            category = "semantic" if category != "combined" else category
        return PromptLeakDecision(
            block=block,
            confidence=confidence,
            category=category,
            semantic_distance=semantic,
            matches=hits,
        )