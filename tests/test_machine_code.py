# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白
"""机器码采集的回归测试。

为什么这些断言必须存在
────────────────────────────────────────────────────────────────
2026-09-28 线上版用户「按界面显示的机器码申请了码，
装上却提示与本机不匹配」。根因有两条，都不会自己暴露：

1. 旧实现取「第一块非移动磁盘的卷标 + 容量」——
   卷标会变、枚举顺序不保证、插拔移动硬盘就变。
2. 机器码算法散落三处（签发工具 / Rust / 引擎），
   没有任何机制保证它们一致。

两条都是**静默**失效：功能测试全绿，用户却拿不到能用的产品。
所以判据必须是「同一台机器反复采集结果相同」与
「采集失败时不得返回空串」，而不是「能跑就行」。
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from daoti_xuandun_personal import license as lic  # noqa: E402


class TestMachineCodeStability:
    def test_repeated_collection_is_identical(self) -> None:
        """同一台机器反复采集必须完全一致。

        ★ 这是本次事故的直接判据。旧实现在插拔设备 /
          改盘符后会变，而用户在申请与激活两个时刻
          拿到的是不同值 —— 码必然验不过。
        """
        first = lic.machine_code()
        second = lic.machine_code()
        assert first == second, "同一台机器两次采集结果不同，机器码不可用"
        assert first, "机器码不得为空串"

    def test_collection_is_case_and_whitespace_insensitive(self) -> None:
        """采集结果不得含前导/尾随空白。

        空白差异会让哈希不同，而用户界面显示的是哈希 ——
        用户复制到的与签发方算出的就会差一个空格。
        """
        raw = lic.machine_code()
        assert raw == raw.strip(), "机器码首尾有空白，会导致哈希不一致"

    def test_segments_are_sorted_and_deduped(self) -> None:
        """各段必须已排序去重。

        WMI 返回顺序不保证。若不排序，同一台机器在
        不同次系统启动中可能给出不同顺序 → 哈希不同。
        """
        raw = lic.machine_code()
        if raw.startswith("hw-unavailable:"):
            pytest.skip("本机取不到稳定硬件 ID")
        segs = raw.split("|")
        assert segs == sorted(segs), f"机器码各段未排序：{segs}"
        assert len(segs) == len(set(segs)), f"机器码含重复段：{segs}"


class TestMachineCodeDegradation:
    def test_no_hardware_id_does_not_return_empty(self) -> None:
        """采集不到硬件 ID 时必须降级，**绝不能返回空串**。

        ★ 空串会让所有用户算出同一个哈希，等于悄悄取消一码一机。
          带 ``hw-unavailable:`` 前缀是为了让签发方一眼看出
          这台机器的码不可靠，从而在签发前就与用户沟通。
        """
        import platform

        saved = lic._run_windows_serials
        saved_mac = lic._run_macos_serials
        try:
            lic._run_windows_serials = lambda: []
            lic._run_macos_serials = lambda: []
            raw = lic.machine_code()
        finally:
            lic._run_windows_serials = saved
            lic._run_macos_serials = saved_mac

        assert raw, "降级路径返回了空串 —— 这等于取消一码一机"
        assert raw.startswith("hw-unavailable:"), f"未标记降级状态：{raw}"
        assert platform.system() in raw

    def test_placeholder_serials_are_rejected(self) -> None:
        """厂商没填的占位序列号必须被剔除。

        混进机器码会让一批同型号机器算出同一个值，
        一码一机直接失效 —— 且这种失效同样是静默的。
        """
        for bad in (
            "TOBEFILLEDBYOEMS",
            "Default string",
            "None",
            "SystemSerialNumber",
            "0000000000",
            "",
        ):
            assert not lic._is_real_serial(bad), f"占位序列号未被剔除：{bad!r}"

    def test_real_serials_are_accepted(self) -> None:
        for good in ("005927501CSG", "BFEBFBFF000906ED", "191059577904885"):
            assert lic._is_real_serial(good), f"真实序列号被误剔除：{good!r}"


class TestMachineCodeHash:
    def test_hash_is_32_hex_chars(self) -> None:
        h = lic.machine_code_hash(lic.machine_code())
        assert len(h) == 32, "必须是 sha256 十六进制的前 32 个字符"
        assert all(c in "0123456789abcdef" for c in h), f"非小写十六进制：{h}"

    def test_hash_ignores_case_and_outer_whitespace(self) -> None:
        """与 Rust 侧 machine_code_hash 语义一致。

        Rust 侧是 ``raw.trim().to_ascii_uppercase()``，
        Python 侧是 ``(machine_code or "").strip().upper()``。
        两边任一改动都会让所有已签发的码失效。
        """
        assert lic.machine_code_hash("ABC") == lic.machine_code_hash(" abc ")
        assert lic.machine_code_hash("abc") == lic.machine_code_hash("ABC")

    def test_different_machines_get_different_hashes(self) -> None:
        assert lic.machine_code_hash("disk-a") != lic.machine_code_hash("disk-b")

    def test_empty_input_still_hashes(self) -> None:
        """空串也必须产出固定哈希，而不是崩或返回空。

        防御性：调用方若传了空值，我们希望得到一个
        可辨识的哈希，而不是空串一路传下去。
        """
        h = lic.machine_code_hash("")
        assert len(h) == 32
