# -*- coding: utf-8 -*-
"""出厂攻击语料生成器 — 将已校准的常见攻击语料固化为出厂资源。

产出：src/daoti_xuandun/resources/attack_v1.json
  [{"category": 分类, "text": 攻击文本}, ...]

设计说明（活性防护哲学）：
- 出厂交付「市面常见攻击」原型，是安全产品开箱即用的必备能力。
- 以纯文本语料资源形式入库，运行时用当前 mapping_key 编码，
  保证原型与运行期洛书空间种子天然一致（种子无关）。
- 禁止硬编码到源码，遵循与 benign_v1.npy 相同的资源化思路。
"""
import importlib.util
import json
import os
import sys

_THIS = os.path.dirname(os.path.abspath(__file__))
_TESTS_DIR = os.path.join(_THIS, "..", "tests")
_RESOURCES = os.path.join(_THIS, "..", "src", "daoti_xuandun", "resources")
_OUT = os.path.join(_RESOURCES, "attack_v1.json")


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main():
    os.makedirs(_RESOURCES, exist_ok=True)
    cb = _load("comprehensive_benchmark", os.path.join(_TESTS_DIR, "comprehensive_benchmark.py"))
    hb = _load("honest_benchmark", os.path.join(_TESTS_DIR, "honest_benchmark.py"))

    sets = {
        "OWASP_LLM01_提示注入": cb.OWASP_LLM01,
        "Garak_编码攻击": cb.GARAK_ENCODING,
        "Garak_续写诱导": cb.GARAK_CONTINUATION,
        "Garak_角色扮演越狱": cb.GARAK_ROLEPLAY,
        "Garak_语言切换": cb.GARAK_LANGSWITCH,
        "Promptfoo_模板注入": cb.PROMPTFOOT_TEMPLATE_INJECTION,
        "Promptfoo_上下文操纵": cb.PROMPTFOOT_CONTEXT_MANIPULATION,
        "Promptfoo_指令覆盖": cb.PROMPTFOOT_INSTRUCTION_OVERRIDE,
        "PII_敏感信息提取": cb.PII_EXTRACTION,
        "系统提示词泄露": cb.PROMPT_LEAK,
        "输出泄露方向": cb.OUTPUT_LEAK_SAMPLES,
        "输出违规方向": cb.OUTPUT_VIOLATION_SAMPLES,
        "多轮会话攻击": cb.MULTITURN_ESCALATION,
        "间接注入": cb.INDIRECT_INJECTION,
        "CyberSec_网络安全": cb.CYBERSEC_ATTACKS,
        "虚假信息生成": hb.MISINFO_ATTACKS,
        "CyberSec_独立困难样本": hb.CYBERSEC_ATTACKS,
    }

    records = []
    seen = set()
    for category, samples in sets.items():
        for text in samples:
            if not isinstance(text, str) or not text.strip():
                continue
            key = text.strip()
            if key in seen:
                continue
            seen.add(key)
            records.append({"category": category, "text": key})

    with open(_OUT, "w", encoding="utf-8") as f:
        json.dump(records, f, ensure_ascii=False, indent=1)
    print(f"已生成 {_OUT}: {len(records)} 条 / {len(sets)} 类", flush=True)


if __name__ == "__main__":
    main()
