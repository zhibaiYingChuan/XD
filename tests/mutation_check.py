# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白
"""守卫类测试的变异验证。

为什么需要这个脚本
────────────────────────────────────────────────────────────────
本轮加的守卫（掩码 Key 报错、测试序号作废）都是「读源码 + 断言」形式。
这类测试最大的风险不是写错，而是**恒真** —— 断言看起来在检查，
实际无论代码怎么坏都能通过。那样它比没有测试更糟：给人虚假的安全感。

判据只有一条：**把守卫改坏，测试必须红**。
所以这里真的去改坏它，跑测试，确认变红，再还原。

用法：
    python tests/mutation_check.py
退出码 0 = 全部变异都被捕获（守卫有效）。
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# (名称, 相对路径, 把守卫改坏的替换规则, 期望失败的测试名片段)
MUTATIONS = [
    (
        "去掉测试序号比对（陈旧结论会覆盖新输入）",
        "desktop/src/pages/Settings.tsx",
        [
            (
                r"if \(!mountedRef\.current \|\| seq !== testSeqRef\.current\) return;",
                "if (!mountedRef.current) return;",
            )
        ],
        "test_stale_test_result_is_discarded",
    ),
    (
        "改地址时不再作废在飞请求",
        "desktop/src/pages/Settings.tsx",
        [
            # 只删地址 onChange 里的那一处。地址处理形如
            #   setConfig({ ...config, relay: { ...config.relay,
            #     base_url: e.target.value } });
            # 后面跟着若干注释行，再是 testSeqRef.current += 1。
            # 全文有多处 testSeqRef.current += 1，不能一刀切删掉。
            (
                r"(base_url: e\.target\.value \} \}\);\s*\n(?:\s*//[^\n]*\n)*\s*)"
                r"testSeqRef\.current \+= 1;",
                r"\1",
            )
        ],
        "test_stale_test_result_is_discarded",
    ),
    (
        "掩码 Key 守卫改回静默 continue",
        "src/daoti_xuandun_personal/proxy/app.py",
        [
            (
                r"raise HTTPException\(\s*status_code=400,\s*detail=\(\s*\"这个 API Key.*?\),\s*\)",
                "continue",
            )
        ],
        "test_update_config_rejects_masked_key_loudly",
    ),
    # ── 拦截依据（2026-10-02）──
    #   阻断路径从不落库 + detail_json 写成 dict，
    #   导致 40 条真实拦截在界面上看起来像 40 次误报。
    (
        "阻断分支不再落库脱敏记录",
        "src/daoti_xuandun_personal/proxy/app.py",
        [
            (
                r"if blocked\.records:\s*\n\s*_storage\.insert_redactions\(\s*\n"
                r"\s*log_id, session_id, blocked\.records\s*\n\s*\)",
                "pass  # 变异：故意不落库",
            )
        ],
        "test_block_branch_writes_redaction_records",
    ),
    (
        "阻断依据改回空记录",
        "src/daoti_xuandun_personal/proxy/sanitizer.py",
        [(r"records=_masked_evidence\(text, deduped\),", "records=[],  # 变异")],
        "test_block_result_carries_evidence_records",
    ),
    (
        "证据不掩码、直接存原文",
        "src/daoti_xuandun_personal/proxy/sanitizer.py",
        [
            (
                r"original=_mask_value\(text\[start:end\]\),",
                "original=text[start:end],  # 变异",
            )
        ],
        "test_evidence_masks_the_original",
    ),
    (
        "detail_json 改回 dict（前端只渲染数组）",
        "src/daoti_xuandun_personal/proxy/app.py",
        [
            (
                r"    out: List\[Dict\[str, Any\]\] = \[\s*\n"
                r'        \{\s*\n\s*"category": "request_blocked",',
                '    out: Dict[str, Any] = {}  # 变异\n    _unused = [\n        {\n'
                '            "category": "request_blocked",',
            ),
            (r"^    return out$", "    return out  # 变异"),
        ],
        "test_detail_json_is_a_list_not_a_dict",
    ),
    (
        "阻断又记进「已打码」计数",
        "src/daoti_xuandun_personal/proxy/app.py",
        [
            (
                r"_storage\.update_daily_stats\(total_calls=1, danger=1\)",
                "_storage.update_daily_stats(total_calls=1, danger=1,"
                " redactions=len(blocked.records))  # 变异",
            )
        ],
        "test_block_branch_does_not_inflate_redaction_counter",
    ),
    (
        "前端不再渲染 evidence 字段",
        "desktop/src/pages/Logs.tsx",
        [(r"\{f\.evidence && \(", "{false && (  # 变异")],
        "test_drawer_renders_evidence_field",
    ),
    (
        "首页刷新按钮不再触发动作",
        "desktop/src/pages/Dashboard.tsx",
        [
            (
                r"onClick=\{\(\) => void handleRefresh\(\)\}\s*\n"
                r"\s*disabled=\{refreshing\}\s*\n\s*aria-label=\"刷新数据\"",
                'onClick={() => undefined}  # 变异\n            disabled={true}\n'
                '            aria-label="刷新数据"',
            )
        ],
        "test_dashboard_has_refresh_button",
    ),
    (
        "刷新时间戳忘了 /1000（秒/毫秒错配）",
        "desktop/src/pages/Dashboard.tsx",
        [
            (
                r"setLastLoadedAt\(Date\.now\(\) / 1000\);",
                "setLastLoadedAt(Date.now());  # 变异",
            )
        ],
        "test_refresh_timestamp_uses_seconds_not_milliseconds",
    ),
    # ── 标记误报必须真的降数（2026-10-02）──
    (
        "标记误报不再回退 daily_stats",
        "src/daoti_xuandun_personal/storage/db.py",
        [
            (
                r"            self\._adjust_daily_stats_for_mark\(entry, delta=-1\)",
                "            pass  # 变异：不再回退统计",
            )
        ],
        "test_marking_a_block_lowers_danger",
    ),
    (
        "标记误报连带回退「安全」计数",
        "src/daoti_xuandun_personal/storage/db.py",
        [
            (
                r'        if entry\.action == Action\.BLOCK\.value:\n'
                r'            col = "danger_count"\n'
                r"        elif entry\.action == Action\.ALERT\.value:\n"
                r'            col = "suspect_count"\n'
                r"        else:\n            return",
                '        col = {"block": "danger_count", "alert": "suspect_count",'
                '\n               "pass": "safe_count"}[entry.action]'
                "  # 变异",
            )
        ],
        "test_marking_pass_does_not_shrink_safe_count",
    ),
    (
        "标记误报时重复扣减（去掉幂等保护）",
        "src/daoti_xuandun_personal/storage/db.py",
        [
            (
                r"        if entry\.marked_safe:\n"
                r"            return True   # 已标记，不重复扣减",
                "        # 变异：幂等保护被去掉",
            )
        ],
        "test_marking_twice_does_not_double_subtract",
    ),
    (
        "取消标记不再把数字加回",
        "src/daoti_xuandun_personal/storage/db.py",
        [
            (
                r"            self\._adjust_daily_stats_for_mark\(entry, delta=1\)",
                "            pass  # 变异：不加回",
            )
        ],
        "test_unmarking_restores_the_count",
    ),
    (
        "计数不再防负数",
        "src/daoti_xuandun_personal/storage/db.py",
        [
            (
                r"SET \{col\} = MAX\(0, \{col\} \+ \?\),\n"
                r"\s*total_calls = MAX\(0, total_calls \+ \?\)",
                "SET {col} = {col} + ?,\n"
                "                    total_calls = total_calls + ?",
            )
        ],
        "test_counts_never_go_negative",
    ),
    (
        "前端又承诺「后续统计不再计入」",
        "desktop/src/pages/Logs.tsx",
        [
            (
                r"toast\.success\('已标记为误报，今日「危险/可疑」计数已减去这一条'\);",
                "toast.success('已标记为误报，后续统计将不再计入风险');"
                "  // 变异",
            )
        ],
        "test_toast_matches_reality",
    ),
    # ── 评分归因（2026-10-02）──
    #   用户看到 0/100，扣分明细 −380。查库发现那 19 次「危险」
    #   全部是「响应长度突变」——用户问了个长问题，
    #   中转站被扣了 380 分。评分算法必须按责任归因。
    (
        "长度突变又算回中转站的责任",
        "src/daoti_xuandun_personal/reputation/tracker.py",
        [
            (
                r"_RELAY_ATTRIBUTABLE: frozenset = frozenset\(\{\n"
                r'    "tool_call_dangerous",',
                '_RELAY_ATTRIBUTABLE: frozenset = frozenset({\n'
                '    "length_anomaly",  # 变异\n'
                '    "tool_call_dangerous",',
            )
        ],
        "test_length_anomaly_is_not_relay_fault",
    ),
    (
        "评分改回按绝对次数累减（会触底）",
        "src/daoti_xuandun_personal/reputation/tracker.py",
        [
            (
                r"            weighted = rep\.relay_danger_count \* 2"
                r" \+ rep\.relay_suspect_count\n"
                r"            ratio = weighted / denominator\n"
                r"            score -= min\(_BEHAVIOR_MAX_PENALTY,"
                r" ratio \* _BEHAVIOR_MAX_PENALTY \* 4\)",
                "            score -= rep.relay_danger_count * 20"
                "  # 变异\n"
                "            score -= rep.relay_suspect_count * 4",
            )
        ],
        "test_score_is_not_bottomed_out",
    ),
    (
        "分母不排除用户自身事件（可被洗白）",
        "src/daoti_xuandun_personal/reputation/tracker.py",
        [
            (
                r"        relay_risk = rep\.relay_danger_count"
                r" \+ rep\.relay_suspect_count\n"
                r"        normal = rep\.total_calls - relay_risk - \(\n"
                r"            rep\.self_danger_count \+ rep\.self_suspect_count\n"
                r"        \)\n"
                r"        denominator = relay_risk \+ max\(0, normal\)",
                "        denominator = rep.total_calls  # 变异",
            )
        ],
        "test_user_side_events_cannot_inflate_the_score",
    ),
    (
        "分母改用 total_calls（用户侧可洗白分数）",
        "src/daoti_xuandun_personal/reputation/tracker.py",
        [
            (
                r"            ratio = weighted / denominator",
                "            ratio = weighted / rep.total_calls  # 变异",
            )
        ],
        "test_user_side_events_cannot_inflate_the_score",
    ),
    (
        "评分不再有下限（可被稀释到 0）",
        "src/daoti_xuandun_personal/reputation/tracker.py",
        [
            (
                r"_BEHAVIOR_MAX_PENALTY = 55\.0",
                "_BEHAVIOR_MAX_PENALTY = 500.0  # 变异",
            )
        ],
        "test_score_never_reaches_zero_from_behaviour_alone",
    ),
    (
        "用户侧事件被算进扣分（可刷分）",
        "src/daoti_xuandun_personal/reputation/tracker.py",
        [
            (
                r"            weighted = rep\.relay_danger_count \* 2"
                r" \+ rep\.relay_suspect_count",
                "            weighted = (rep.relay_danger_count"
                " + rep.self_danger_count) * 2"
                " + rep.relay_suspect_count + rep.self_suspect_count"
                "  # 变异",
            )
        ],
        "test_user_side_events_cannot_inflate_the_score",
    ),
    (
        "水印扣分被稀释进比例",
        "src/daoti_xuandun_personal/reputation/tracker.py",
        [
            (
                r"        if rep\.watermark_detected:\n"
                r"            score -= _WATERMARK_PENALTY",
                "        if rep.watermark_detected:\n"
                "            score -= _WATERMARK_PENALTY / 10  # 变异",
            )
        ],
        "test_watermark_penalised_once_and_hard",
    ),
    (
        "恶意库不再直接归零",
        "src/daoti_xuandun_personal/reputation/tracker.py",
        [
            (
                r"        if rep\.known_malicious:\n            return 0",
                "        # 变异：不再直接归零",
            )
        ],
        "test_known_malicious_still_zeroes_it",
    ),
    (
        "前端扣分权重与后端脱钩",
        "desktop/src/pages/Dashboard.tsx",
        [
            (
                r"  watermark: 30,",
                "  watermark: 10,  # 变异",
            )
        ],
        "test_weights_match_backend_constants",
    ),
    (
        "新字段不落库（重启后归因丢失）",
        "src/daoti_xuandun_personal/storage/db.py",
        [
            (
                r"                    rep\.relay_danger_count, rep\.self_danger_count,\n"
                r"                    rep\.relay_suspect_count, rep\.self_suspect_count,",
                "                    0, 0, 0, 0,  # 变异",
            )
        ],
        "test_new_columns_survive_round_trip",
    ),
    (
        "导入时不重算分数（沿用旧算法的错值）",
        "src/daoti_xuandun_personal/reputation/tracker.py",
        [
            (
                r"        rep\.score = self\._compute_score\(rep\)\n"
                r"        self\._reputations\[rep\.domain\] = rep",
                "        # 变异：不重算\n"
                "        self._reputations[rep.domain] = rep",
            )
        ],
        "test_score_is_recomputed_on_load",
    ),
    (
        "重算结果不写回库（内存对库里错）",
        "src/daoti_xuandun_personal/proxy/app.py",
        [
            (
                r"        _reputation\.import_reputation\(rep\)\n"
                r"        try:\n"
                r"            _storage\.upsert_reputation\(rep\)\n"
                r"        except Exception as e:  # noqa: BLE001\n"
                r"            # 重算后的分数写回失败不应阻断启动：\n"
                r"            # 内存里的值已经是正确的，接口照常可用。\n"
                r"            logger\.warning\(\"信誉分数回写失败（内存值仍正确）: %s\", e\)",
                "        _reputation.import_reputation(rep)  # 变异：不回写",
            )
        ],
        "test_startup_recomputes_and_persists",
    ),
    # ── 多中转站（2026-10-02）──
    #   用户同时用两家时，代理无条件用配置里的 Key 覆盖 Authorization，
    #   「以为在用 A、实际扣 B 的钱」。且每次保存配置会把
    #   其余中转站的真实 Key 全换成掩码串。
    (
        "转发时又用启用项的 Key 覆盖（按 Key 识别被推平）",
        "src/daoti_xuandun_personal/proxy/app.py",
        [
            (
                r"        target = resolve_forward_target\(target\)\n"
                r'        base = target\["base"\]\n'
                r'        api_key = target\["api_key"\]',
                "        # 变异：忽略解析结果，直接用启用项\n"
                '        base = normalize_relay_base(_config.relay.base_url)\n'
                "        api_key = _config.relay.api_key",
            )
        ],
        "test_route_really_sends_the_target_relays_key",
    ),
    (
        "_resolve_upstream 又变回 async（调用处漏 await → 每个请求 500）",
        "src/daoti_xuandun_personal/proxy/app.py",
        [
            (
                r"def _resolve_upstream\(request\) -> "
                r"Optional\[Dict\[str, Any\]\]:",
                "async def _resolve_upstream(request) -> "
                "Optional[Dict[str, Any]]:  # 变异",
            )
        ],
        "test_route_really_sends_the_target_relays_key",
    ),
    (
        "转发时不看 target，直接用 all_relays()[0]",
        "src/daoti_xuandun_personal/proxy/app.py",
        [
            (
                r"    relay_cfg = _config\.relay\n"
                r"    if target is None:\n"
                r"        target = relay_cfg\.all_relays\(\)\[0\]",
                "    relay_cfg = _config.relay\n"
                "    target = relay_cfg.all_relays()[0]  # 变异：忽略传入目标",
            )
        ],
        "test_forward_target_carries_its_own_key",
    ),
    (
        "转发时用启用项的 Key 覆盖目标的 Key",
        "src/daoti_xuandun_personal/proxy/app.py",
        [
            (
                r'        "api_key": str\(target\.get\("api_key"\) '
                r"or relay_cfg\.api_key\),",
                '        "api_key": relay_cfg.api_key,  # 变异：无条件覆盖',
            )
        ],
        "test_forward_target_carries_its_own_key",
    ),
    (
        "配置列表接口下发明文 Key",
        "src/daoti_xuandun_personal/proxy/app.py",
        [
            (
                r'"api_key_masked": mask_relay_key\(\s*'
                r'str\(r\.get\("api_key"\) or ""\)\),',
                '"api_key_masked": r.get("api_key"),  # 变异',
            )
        ],
        "test_configured_endpoint_masks_every_key",
    ),
    (
        "to_safe_dict 不再掩码列表里的 Key",
        "src/daoti_xuandun_personal/config.py",
        [
            (
                r'        relay\["others"\] = \[\s*\n'
                r'            \{\*\*r, "api_key": mask_relay_key\('
                r'str\(r\.get\("api_key"\) or ""\)\)\}\s*\n'
                r"            for r in self\.relay\.others\s*\n        \]",
                "        # 变异：others 原样输出\n"
                "        relay['others'] = list(self.relay.others)",
            )
        ],
        "test_safe_dict_masks_others",
    ),
    (
        "保存配置时不再校验列表里的掩码 Key",
        "src/daoti_xuandun_personal/proxy/app.py",
        [
            (
                r"    for i, item in enumerate\(others or \[\]\):\s*\n"
                r"        if not isinstance\(item, dict\):\s*\n"
                r"            continue\s*\n"
                r'        key = str\(item\.get\("api_key"\) or ""\)\s*\n'
                r"        if is_masked_key\(key\):\s*\n"
                r"            return i, key",
                "    return None  # 变异：不再校验",
            )
        ],
        "test_backend_rejects_masked_key_in_others",
    ),
    (
        "掩码守卫只报下标不报值（错误文案会指错家）",
        "src/daoti_xuandun_personal/proxy/app.py",
        [
            (
                r"            return i, key",
                "            return i, ''  # 变异：丢掉具体值",
            )
        ],
        "test_masked_guard_finds_the_offending_index",
    ),
    (
        "切换中转站时不备份当前项（切走即删除）",
        "src/daoti_xuandun_personal/proxy/app.py",
        [
            (
                r"    relay_cfg\.others = \[current_backup\] \+ remaining",
                "    relay_cfg.others = remaining  # 变异：丢弃当前项",
            )
        ],
        "test_switching_does_not_lose_configuration",
    ),
    (
        "按 Key 识别改为只认第一项",
        "src/daoti_xuandun_personal/config.py",
        [
            (
                r"        for r in self\.all_relays\(\):\s*\n"
                r'            if r\.get\("api_key"\) and r\["api_key"\] '
                r"== api_key:\s*\n                return r",
                "        return self.all_relays()[0]  # 变异：不比对 Key",
            )
        ],
        "test_matching_key_returns_that_relay",
    ),
    (
        "未识别的 Key 不再回退，直接报错",
        "src/daoti_xuandun_personal/proxy/app.py",
        [
            (
                r"    matched = relay_cfg\.relay_by_key\(incoming\) "
                r"if incoming else None",
                "    matched = relay_cfg.relay_by_key(incoming)"
                " if incoming else None\n"
                "    if incoming and matched is None:\n"
                "        raise ValueError('未识别的 Key')  # 变异",
            )
        ],
        "test_resolve_upstream_falls_back_to_active",
    ),
    (
        "风险又记到当前启用项头上（串台）",
        "src/daoti_xuandun_personal/proxy/app.py",
        [
            (
                r'        rep = _reputation\.record_call\(\s*\n'
                r'            domain if domain\.startswith\("http"\) '
                r'else f"https://\{domain\}",',
                "        rep = _reputation.record_call(\n"
                "            _config.relay.base_url,  # 变异：串台",
            )
        ],
        "test_record_reputation_respects_domain_argument",
    ),
    (
        "配置列表改用 /api/relays（与信誉列表撞车成死代码）",
        "src/daoti_xuandun_personal/proxy/app.py",
        [
            (
                r'@app\.get\("/api/relays/configured"\)',
                '@app.get("/api/relays")  # 变异：与信誉列表同名',
            )
        ],
        "test_no_duplicate_routes",
    ),
    (
        "切换接口不再重建列表（目标项留在列表里重复）",
        "src/daoti_xuandun_personal/proxy/app.py",
        [
            (
                r"    remaining = \[\s*\n"
                r'        r for r in relay_cfg\.others '
                r"if str\(r\.get\(\"id\"\) or \"\"\) != want\s*\n    \]",
                "    remaining = relay_cfg.others  # 变异：不剔除目标项",
            )
        ],
        "test_switch_keeps_all_relays",
    ),
    (
        "切到自己也算一次变更（列表里会多出重复项）",
        "src/daoti_xuandun_personal/proxy/app.py",
        [
            (
                r"    if want == cur_id:\s*\n"
                r'        return \{"ok": True, "active_id": want, '
                r'"changed": False\}',
                "    # 变异：不再短路，继续往下走",
            )
        ],
        "test_switch_reports_when_nothing_changed",
    ),
    (
        "「表单已打开」又和「请求在飞」共用一个 state",
        "desktop/src/pages/Settings.tsx",
        [
            (
                r"\{addingBusy \? '添加中…' : '添加到列表'\}",
                "{addingBusy ? '添加到列表' : '添加到列表'}"
                "  # 变异：不再区分请求态",
            ),
            (
                r"\{adding \? \(\s*<>\s*\n(\s*)<div className=\"field-label\">"
                r"添加中转站</div>",
                "{addingBusy ? (\n\\1<div className=\"field-label\">"
                "添加中转站</div>",
            ),
        ],
        "test_form_open_state_is_not_the_request_state",
    ),
    (
        "新增按钮不再禁用（可连点重复提交）",
        "desktop/src/pages/Settings.tsx",
        [
            (
                r"                    disabled=\{addingBusy\}\n"
                r"                    onClick=\{\(\) => void addRelay\(\)\}",
                "                    onClick={() => void addRelay()}"
                "  # 变异：不禁用",
            )
        ],
        "test_form_open_state_is_not_the_request_state",
    ),
    (
        "新增后调用 load()（会清掉用户填到一半的表单）",
        "desktop/src/pages/Settings.tsx",
        [
            (
                r"      await loadConfigured\(\);\n"
                r"      setNewRelay\(",
                "      await load();  # 变异：多余的重载\n"
                "      await loadConfigured();\n"
                "      setNewRelay(",
            )
        ],
        "test_frontend_add_does_not_touch_current_item",
    ),
    (
        "新增接口接受掩码 Key（静默且不可逆）",
        "src/daoti_xuandun_personal/proxy/app.py",
        [
            (
                r"        if not api_key:\n"
                r'            errors\.append\("中转站 API Key 不能为空"\)\n'
                r"        elif is_masked_key\(api_key\):",
                "        if not api_key:\n"
                '            errors.append("中转站 API Key 不能为空")\n'
                "        elif False:  # 变异：不再拒绝掩码",
            )
        ],
        "test_add_rejects_masked_key",
    ),
    (
        "新增允许重复添加当前那家（列表出现重复项）",
        "src/daoti_xuandun_personal/proxy/app.py",
        [
            (
                r"        if new_id == relay_cfg\.make_relay_id\(\s*\n"
                r"                relay_cfg\.base_url, relay_cfg\.api_key\):",
                "        if False:  # 变异：不检查重复",
            )
        ],
        "test_add_rejects_the_current_one",
    ),
    (
        "允许移除当前启用项（AI 工具立刻失去目标）",
        "src/daoti_xuandun_personal/proxy/app.py",
        [
            (
                r"        if want == cur_id or want == relay_cfg\.active_id:",
                "        if False:  # 变异：允许移除启用项",
            )
        ],
        "test_remove_refuses_the_active_one",
    ),
    (
        "移除时把所有中转站都清掉",
        "src/daoti_xuandun_personal/proxy/app.py",
        [
            (
                r"        relay_cfg\.others = \[\s*\n"
                r'            r for r in relay_cfg\.others '
                r"if str\(r\.get\(\"id\"\) or \"\"\) != want\s*\n        \]",
                "        relay_cfg.others = []  # 变异：一锅端",
            )
        ],
        "test_remove_drops_only_that_one",
    ),
    (
        "前端把 add_relay 的键名写成 snake_case（Tauri 找不到）",
        "desktop/src/services/api.ts",
        [
            (
                r"      \{\n        name: relay\.name,\n"
                r"        baseUrl: relay\.base_url,\n"
                r"        apiKey: relay\.api_key,\n      \}\),",
                "      {  # 变异：Tauri 只认 camelCase\n"
                "        name: relay.name,\n"
                "        base_url: relay.base_url,\n"
                "        api_key: relay.api_key,\n"
                "      }),",
            )
        ],
        "test_tauri_arg_shapes_match_the_rust_signatures",
    ),
    (
        "切换时不存在的 id 静默成功",
        "src/daoti_xuandun_personal/proxy/app.py",
        [
            (
                r"    if target is None:\s*\n        raise KeyError\(want\)",
                "    if target is None:\n"
                "        return {'ok': True, 'active_id': want,"
                " 'changed': False}  # 变异",
            )
        ],
        "test_switch_unknown_id_raises",
    ),
    # ── 版本号一致性（2026-10-02）──
    #   版本散落在 9 个文件里且此前无任何检查。
    #   漏改一处不会编译失败、不会测试变红，
    #   只会让「安装包文件名 / 界面显示 / /api/docs」互相矛盾 ——
    #   而每一处单独看都是真的。
    (
        "tauri.conf.json 漏改版本（安装包与界面显示矛盾）",
        "desktop/src-tauri/tauri.conf.json",
        [(r'"version": "0\.1\.1-alpha"', '"version": "0.1.0-alpha"')],
        "test_every_file_declares_the_same_version",
    ),
    (
        "界面版本号漏改（Layout 与引擎自报不一致）",
        "desktop/src/components/Layout.tsx",
        [(r"useState\('0\.1\.1-alpha'\)", "useState('0.1.0-alpha')")],
        "test_every_file_declares_the_same_version",
    ),
    (
        "锁文件里的本包版本漏改（CI 会复用旧依赖）",
        "desktop/src-tauri/Cargo.lock",
        [
            (
                r'(name = "xuandun-personal"\nversion = ")0\.1\.1-alpha',
                r"\g<1>0.1.0-alpha",
            )
        ],
        "test_our_own_entry_in_lockfiles",
    ),
    (
        "剥注释时把 docstring 也当声明（判据误报）",
        "tests/test_help_claims.py",
        [
            (
                r"        text = re\.sub\(r'\(\?s\)\"\"\"\(\?:\.\|\\n\)\*\?\"\"\"', "
                r"'', text\)\n"
                r"        text = re\.sub\(r\"\(\?s\)'''\(\?:\.\|\\n\)\*\?'''\", "
                r"'', text\)",
                "        # 变异：不剥 docstring",
            )
        ],
        "test_comment_stripping_does_not_hide_declarations",
    ),
]


def run_tests(pattern: str) -> tuple[int, str]:
    proc = subprocess.run(
        [
            sys.executable, "-m", "pytest",
            "tests/test_relay_config.py", "tests/test_block_evidence.py",
            "tests/test_reputation_score.py", "tests/test_multi_relay.py",
            "tests/test_help_claims.py",
            "-q", "-k", pattern, "--tb=line", "-rf",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    # ★★ 这里必须只保留 pytest 的**摘要行**，丢弃其余全部输出。
    #
    #   踩过的坑：判据要读 Logs.tsx / Dashboard.tsx 源码，
    #   pytest 会把断言失败时的源码片段整段打进输出，
    #   「FAILED ...::test_xxx」摘要行被顶到上万字符之外。
    #   于是只截尾部 → 漏掉摘要行 → 明明红了却判成
    #   「红的是别的用例」。
    #
    #   --tb=line 也**不足以**解决：断言消息本身
    #   就包含整份源码（不是 traceback 才带），
    #   所以正确做法是主动过滤，只留含 FAILED/PASSED 的行。
    #   这比调大截取长度可靠 —— 后者只是把阈值往后挪，
    #   源码再长一点又会漏。
    lines = [
        ln for ln in (proc.stdout or "").splitlines()
        if "FAILED" in ln or "passed" in ln or "failed" in ln
        or "error" in ln.lower()
    ]
    return proc.returncode, "\n".join(lines)


def _named_test_failed(out: str, expect: str) -> bool:
    """确认**指定的那条**判据报红，而不是随便哪条红了。

    ★ 为什么必须这么严
      只看「整体红没红」是不够的：变异可能意外弄坏了别的用例，
      于是 exit code 非零，但我们要验的那条判据其实没被测到。
      那等于用一条假判据冒充真判据 ——
      比没有变异验证更糟，因为它给了虚假的安全感。
    """
    return expect in out


def main() -> int:
    print("=" * 72)
    print("  守卫测试的变异验证 —— 把守卫改坏，测试必须红")
    print("=" * 72)

    # 先确认基线是绿的
    rc, out = run_tests("")
    if rc != 0:
        print("[FATAL] 基线就已经不是绿的，无法评估变异：")
        print(out[-1500:])
        return 2
    print("  基线: 绿")

    all_caught = True
    for name, rel, rules, expect in MUTATIONS:
        target = ROOT / rel
        backup = Path(tempfile.mkdtemp()) / Path(rel).name
        shutil.copy2(target, backup)
        text = original = target.read_text(encoding="utf-8")

        hit = False
        for pat, rep in rules:
            text, n = re.subn(pat, rep, text, flags=re.S)
            hit = hit or n > 0
        if not hit:
            print(f"\n  [SKIP] {name}")
            print("        变异规则没匹配到源码 —— 规则本身可能已过时，")
            print("        这本身就是需要人看的问题。")
            shutil.copy2(backup, target)
            all_caught = False
            continue

        target.write_text(text, encoding="utf-8")
        try:
            rc, out = run_tests(expect)
        finally:
            shutil.copy2(backup, target)

        # ── 判据：既要看整体红，也要确认是**指定那条**红 ──
        long_out = out
        caught = rc != 0 and _named_test_failed(long_out, expect)
        print(f"\n  [{'PASS' if caught else 'FAIL'}] {name}")
        if caught:
            first = [
                ln for ln in long_out.splitlines()
                if expect in ln and ("AssertionError" in ln or "assert" in ln)
            ]
            if not first:
                first = [
                    ln for ln in long_out.splitlines()
                    if "AssertionError" in ln or "assert" in ln
                ]
            if first:
                print(f"        {first[0].strip()[:110]}")
        elif rc != 0:
            print(f"        测试变红了，但红的是别的用例 —— 期望 {expect}，")
            print("        说明这条判据没被测到，却拿了别人的红当证据。")
            all_caught = False
        else:
            print("        测试仍然绿 —— 守卫没有真正被测到，这条断言是恒真的")
            all_caught = False

    # 还原确认
    for _, rel, _, _ in MUTATIONS:
        pass  # 每次变异都已即时还原

    print()
    print("=" * 72)
    if all_caught:
        print("  结论: 全部变异都被捕获 —— 守卫确实在被测")
        return 0
    print("  结论: 存在未被捕获的变异 —— 有断言是恒真的，必须修")
    return 1


if __name__ == "__main__":
    sys.exit(main())
