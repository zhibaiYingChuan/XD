# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白

"""开发/测试与稳定版的隔离契约。

★ 为什么要把这几条写成测试
────────────────────────────────────────────────────────────────
用户已从线上仓库装了稳定版并正常使用，而开发与 CDP 测试会真实
改动用户数据：写配置、切中转站、造日志。
隔离一旦失效，**没有任何报错**——界面照常显示，只是用户正在用的
中转站配置被测试改掉了。这类损害在事后才暴露，且难以还原。

因此这里锁住三件事：
  ① 三处路径解析（config / db / license）都走同一个 data_dir()
  ② 设了 XUANDUN_DATA_DIR 后，配置与库确实落到该目录
  ③ Rust 侧与 CDP 脚本用的是**同一组**环境变量名 ——
     名字对不上时隔离是假的：一边改了目录，另一边还在读稳定版。
"""

from __future__ import annotations

import importlib
import os
import re
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
SRC = REPO / "src" / "daoti_xuandun_personal"

# 与其他测试文件一致：仓库未安装为包，需手动把 src 加进路径
if str(REPO / "src") not in sys.path:
    sys.path.insert(0, str(REPO / "src"))
RUST_LIB = REPO / "desktop" / "src-tauri" / "src" / "lib.rs"
RUST_LICENSE = REPO / "desktop" / "src-tauri" / "src" \
    / "license.rs"
CDP_SCRIPT = REPO / "tests" / "cdp_desktop_regression.py"


class TestDataDirIsSingleSourced:
    """① 所有落盘路径都必须经过 paths.data_dir()。"""

    def test_paths_module_exists(self):
        assert (SRC / "paths.py").is_file(), (
            "缺少 paths.py —— 数据目录解析必须只有一个入口"
        )

    @pytest.mark.parametrize("rel,reason", [
        ("config.py", "config.json 从这里读写"),
        ("storage/db.py", "数据库从这里读写"),
        ("license.py", "激活状态与吊销名单从这里读写"),
        ("proxy/app.py", "引擎侧读激活状态"),
    ])
    def test_no_hardcoded_app_dir(self, rel, reason):
        """★ 判据：目标文件里不得再自己拼 %LOCALAPPDATA%/com.daoti...。

        只看「有没有调用 paths」不够 —— 很可能调用了 paths 同时
        又留了一处硬编码，那一处照样会写稳定版目录。
        """
        src = (SRC / rel).read_text(encoding="utf-8")
        # 去掉注释行后再查：注释里说明历史来由是允许的
        code = "\n".join(
            ln for ln in src.splitlines() if not ln.strip().startswith("#")
        )
        assert '"com.daoti.xuandun-personal"' not in code, (
            f"{rel} 里仍硬编码了应用目录名（{reason}）。"
            f"改走 paths.data_dir()，否则隔离对它无效"
        )

    def test_paths_env_var_is_read(self):
        src = (SRC / "paths.py").read_text(encoding="utf-8")
        assert "XUANDUN_DATA_DIR" in src, (
            "paths.data_dir() 没有读 XUANDUN_DATA_DIR —— "
            "设了也没用，隔离形同虚设"
        )


class TestIsolationActuallyWorks:
    """② 设了环境变量后，读写确实落到独立目录。"""

    def test_config_file_follows_data_dir(self, tmp_path, monkeypatch):
        from daoti_xuandun_personal import config, paths

        monkeypatch.setenv("XUANDUN_DATA_DIR", str(tmp_path))
        # 模块级常量在 import 时就固定了，必须重新加载才生效
        try:
            importlib.reload(paths)
            importlib.reload(config)

            assert config.CONFIG_FILE == tmp_path / "config.json"
            # 落盘验证：真写一次，确认文件确实在隔离目录里
            cfg = config.PersonalConfig()
            cfg.relay.base_url = "https://relay.example.invalid"
            cfg.relay.api_key = "sk-isolation-probe"
            saved = cfg.save()
            assert saved.parent == tmp_path, (
                f"配置写到了 {saved.parent}，隔离目录是 {tmp_path}"
            )
            assert (tmp_path / "config.json").is_file()
        finally:
            monkeypatch.delenv("XUANDUN_DATA_DIR", raising=False)
            importlib.reload(paths)
            importlib.reload(config)

    def test_db_path_follows_data_dir(self, tmp_path, monkeypatch):
        from daoti_xuandun_personal import paths
        from daoti_xuandun_personal.storage import db as db_mod

        monkeypatch.setenv("XUANDUN_DATA_DIR", str(tmp_path))
        try:
            importlib.reload(paths)
            importlib.reload(db_mod)
            assert db_mod.default_db_path() == tmp_path \
                / "xuandun_personal.db", (
                "数据库没有跟随 XUANDUN_DATA_DIR —— "
                "测试日志会写进用户稳定版的真实统计"
            )
        finally:
            monkeypatch.delenv("XUANDUN_DATA_DIR", raising=False)
            importlib.reload(paths)
            importlib.reload(db_mod)


class TestRustMatchesPython:
    """③ Rust 侧与 Python 侧必须用同一组变量名。"""

    @pytest.mark.parametrize("var", [
        "XUANDUN_DATA_DIR",
        "XUANDUN_PROXY_PORT",
        "XUANDUN_CDP_PORT",
    ])
    def test_var_name_known_to_rust(self, var):
        src = RUST_LIB.read_text(encoding="utf-8")
        assert var in src, (
            f"Rust 侧不认识 {var} —— "
            f"桌面端会去读稳定版数据，隔离只在引擎侧生效"
        )

    def test_rust_license_follows_data_dir(self):
        src = RUST_LICENSE.read_text(encoding="utf-8")
        assert "XUANDUN_DATA_DIR" in src, (
            "license.rs 不认 XUANDUN_DATA_DIR —— "
            "开发版会去改用户稳定版的激活状态（已激活会凭空变成未激活）"
        )

    def test_engine_child_inherits_data_dir(self):
        """★ 桌面端必须把数据目录透传给引擎子进程。

        漏了这一步，引擎会按自己的默认路径读**稳定版**的 config.json：
        开发版界面显示的配置与引擎实际用的不是同一份，
        用户在开发版里改了地址，引擎仍按稳定版的旧地址转发。
        """
        src = RUST_LIB.read_text(encoding="utf-8")
        block = src.split("fn start_engine_process")[1].split("\nfn ")[0]
        assert re.search(
            r"\.env\(\s*env_keys::DATA_DIR", block), (
            "拉起引擎时没有透传 XUANDUN_DATA_DIR —— "
            "隔离只做了一半，引擎仍读稳定版配置"
        )

    def test_cdp_port_not_hardcoded(self):
        """★ CDP 端口必须可换。

        两个 WebView2 都监听 9224 时，先启动的占住端口，
        CDP 连到的是**另一个进程** —— 于是测试驱动的是用户
        正在使用的稳定版窗口。
        """
        src = RUST_LIB.read_text(encoding="utf-8")
        fn = src.split("fn enable_cdp_debug_port")[1].split("\n}")[0]
        assert "--remote-debugging-port=9224" not in fn, (
            "CDP 端口写死在 9224，无法与稳定版错开"
        )
        assert "cdp_port()" in fn, "enable_cdp_debug_port 没有用可配置的端口"


class TestCdpScriptRefusesStableProfile:
    """④ CDP 脚本必须在稳定版数据目录上主动拒绝执行。"""

    def test_script_has_isolation_profile(self):
        src = CDP_SCRIPT.read_text(encoding="utf-8")
        assert "XUANDUN_DATA_DIR" in src
        assert "XUANDUN_CDP_PORT" in src
        assert "XUANDUN_PROXY_PORT" in src

    def test_script_defaults_are_isolated_from_stable(self):
        """★ 默认端口必须与稳定版错开，且不能与本项目其他服务的端口相撞。

        判据不是「读环境变量」而是**默认值**：
        用户直接 `python tests/cdp_desktop_regression.py` 而不设任何
        环境变量时，跑的就是默认档案 —— 那是最常见的执行方式。

        ★ 18766 也不能用：记忆库记载企业版网关曾跑 uvicorn 于 18766。
          撞端口的症状只是超时，排查方向会被带偏到「引擎起不来」，
          而真实原因是「连到了别的服务」。
        """
        src = CDP_SCRIPT.read_text(encoding="utf-8")
        taken = {
            "9224": "稳定版 WebView2 CDP",
            "18765": "稳定版引擎",
            "18766": "企业版网关 uvicorn（历史占用）",
            "1420": "Vite 开发服务器",
            "9222": "LRC Desktop CDP",
            "9223": "网关真 Edge CDP",
            "5173": "控制台 Vite",
        }
        m = re.search(r'CDP_PORT = int\(os\.getenv\("XUANDUN_CDP_PORT", "(\d+)"\)', src)
        assert m, "CDP 端口没有默认值"
        assert m.group(1) not in taken, (
            f"CDP 默认端口 {m.group(1)} 与「{taken[m.group(1)]}」相撞"
        )
        m = re.search(
            r'DEFAULT_PROXY_PORT = int\(os\.getenv\("XUANDUN_PROXY_PORT", "(\d+)"\)', src)
        assert m, "引擎端口没有默认值"
        assert m.group(1) not in taken, (
            f"引擎默认端口 {m.group(1)} 与「{taken[m.group(1)]}」相撞"
        )
        # 两个默认端口还必须彼此不同
        assert m.group(1) != "19231", "引擎端口与 CDP 端口不应相同"

    def test_script_refuses_when_same_as_stable(self):
        src = CDP_SCRIPT.read_text(encoding="utf-8")
        assert "assert_isolated_profile" in src, (
            "脚本没有「拒绝在稳定版目录上执行」这道闸门"
        )
        # 闸门必须在启动桌面端之前被调用
        assert re.search(
            r"if not assert_isolated_profile\(\):", src), (
            "闸门没有被调用 —— 写了函数但从不执行等于没有"
        )
        call_at = src.index("if not assert_isolated_profile():")
        launch_at = src.index("proc = launch_desktop()")
        assert call_at < launch_at, (
            "闸门在拉起桌面端之后才调用 —— "
            "那时配置已经被改 stable 版了"
        )

    def test_script_backup_follows_isolation(self):
        """★ 备份/还原必须跟着隔离目录走。

        否则会出现最坏组合：备份的是开发版配置（测试后还原成
        「未配置」），而用户稳定版的配置被测试改掉且没人还原。
        """
        src = CDP_SCRIPT.read_text(encoding="utf-8")
        fn = src.split("def config_file()")[1].split("\n\n\n")[0]
        assert "data_dir()" in fn, (
            "config_file() 没走隔离目录 —— "
            "备份/还原会作用在稳定版的真实配置上"
        )