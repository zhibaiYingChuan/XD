# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白
# 本文件受道体研究许可证 v1.0 约束，禁止逆向工程和再分发
# 详见 LICENSE 文件

"""MITRE ATLAS 映射模块 — 将拦截事件映射到 MITRE ATLAS 攻击技术编号。

MITRE ATLAS (Adversarial Threat Landscape for Artificial-Intelligence Systems)
是针对 AI 系统的对抗性威胁知识库，本模块将玄盾拦截事件映射到对应的
ATLAS 技术编号，便于安全事件分类、报告和态势感知。
"""

# 攻击类型 → ATLAS 技术映射表
_ATLAS_MAPPINGS: dict[str, dict] = {
    "提示注入": {
        "technique_id": "AML.T0051",
        "technique_name": "Prompt Injection",
        "tactic": "Initial Access",
    },
    "越狱": {
        "technique_id": "AML.T0054",
        "technique_name": "Jailbreak",
        "tactic": "Initial Access",
    },
    "编码攻击": {
        "technique_id": "AML.T0052",
        "technique_name": "Encoding Attack",
        "tactic": "Defense Evasion",
    },
    "角色扮演": {
        "technique_id": "AML.T0053",
        "technique_name": "Role-play Attack",
        "tactic": "Initial Access",
    },
    "数据渗出": {
        "technique_id": "AML.T0047",
        "technique_name": "Data Exfiltration",
        "tactic": "Exfiltration",
    },
    "模型窃取": {
        "technique_id": "AML.T0040",
        "technique_name": "Model Extraction",
        "tactic": "Exfiltration",
    },
    "供应链注入": {
        "technique_id": "AML.T0056",
        "technique_name": "Supply Chain Compromise",
        "tactic": "Initial Access",
    },
    "社会工程": {
        "technique_id": "AML.T0055",
        "technique_name": "Social Engineering",
        "tactic": "Initial Access",
    },
    "多轮渐进攻击": {
        "technique_id": "AML.T0057",
        "technique_name": "Multi-turn Attack",
        "tactic": "Execution",
    },
    "混淆攻击": {
        "technique_id": "AML.T0058",
        "technique_name": "Obfuscation Attack",
        "tactic": "Defense Evasion",
    },
}

# 拦截阶段 → 攻击类型映射（一个阶段可能关联多种攻击类型）
_REJECT_STAGE_TO_ATTACK_TYPES: dict[str, list[str]] = {
    "domain_awareness": ["提示注入", "越狱", "角色扮演"],
    "timing_checker": ["多轮渐进攻击"],
    "input_too_long": ["编码攻击", "混淆攻击"],
    "unicode_anomaly": ["编码攻击", "混淆攻击"],
    "binary_anomaly": ["编码攻击", "混淆攻击"],
    "decoded_payload": ["编码攻击", "提示注入"],
    "luoshu_veto": ["提示注入", "越狱"],
    "structural_anomaly": ["混淆攻击", "编码攻击"],
    "imperative_attack": ["提示注入", "越狱", "角色扮演"],
    "data_exfiltration": ["数据渗出"],
    "model_extraction": ["模型窃取"],
    "supply_chain": ["供应链注入"],
    "social_engineering": ["社会工程"],
}


def map_reject_stage_to_atlas(reject_stage: str) -> list[str]:
    """将拦截阶段映射到 MITRE ATLAS 技术编号列表。

    一个拦截阶段可能关联多种攻击类型，每种攻击类型对应一个
    ATLAS 技术编号。返回去重后的技术编号列表。

    Args:
        reject_stage: 拦截阶段名称，如 "domain_awareness"。

    Returns:
        ATLAS 技术编号列表，如 ["AML.T0051", "AML.T0054"]。
        若阶段未知，返回空列表。
    """
    attack_types = _REJECT_STAGE_TO_ATTACK_TYPES.get(reject_stage, [])
    technique_ids = []
    seen = set()
    for at in attack_types:
        mapping = _ATLAS_MAPPINGS.get(at)
        if mapping and mapping["technique_id"] not in seen:
            technique_ids.append(mapping["technique_id"])
            seen.add(mapping["technique_id"])
    return technique_ids


def map_attack_type_to_atlas(attack_type: str) -> dict:
    """将攻击类型映射到 MITRE ATLAS 技术详情。

    Args:
        attack_type: 攻击类型名称，如 "提示注入"。

    Returns:
        包含 technique_id, technique_name, tactic 的字典。
        若攻击类型未知，返回空字典。
    """
    mapping = _ATLAS_MAPPINGS.get(attack_type)
    if mapping is None:
        return {}
    return {
        "technique_id": mapping["technique_id"],
        "technique_name": mapping["technique_name"],
        "tactic": mapping["tactic"],
    }


def get_all_atlas_mappings() -> dict:
    """获取全部 ATLAS 映射表。

    Returns:
        完整的攻击类型 → ATLAS 技术映射字典。
    """
    return dict(_ATLAS_MAPPINGS)
