# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白

"""P1 跨语言契约回归（第二轮审查 2026-10-28）。

这些问题的共同点是：**单侧永远发现不了**。
  · 端口环境变量两侧名字不同 → 各自都"正常"，只有用户看到引擎起不来
  · 三套超时没有顺序约束 → 客户端超时了，服务端还在发请求
  · 错误体只认一种形态 → 422 校验错误退化成一句 "HTTP 500"
  · @property 不进 asdict → 响应里少一个字段，界面显示空白

判据尽量落在真实调用点；确实只能在另一种语言里执行的部分，
用「两侧必须同时满足的同一条契约」来锁（而不是断言某段文案）。
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from daoti_xuandun_personal.config import PersonalConfig  # noqa: E402
from daoti_xuandun_personal.types import RelayReputation  # noqa: E402

APP_PY = ROOT / "src" / "daoti_xuandun_personal" / "proxy" / "app.py"
LIB_RS = ROOT / "desktop" / "src-tauri" / "src" / "lib.rs"
API_TS = ROOT / "desktop" / "src" / "services" / "api.ts"


# ══════════════════════════════════════════════════════════════
# P1-9：端口环境变量名必须两侧一致
# ══════════════════════════════════════════════════════════════


class TestPortEnvNameAgreement:
    def test_python_accepts_canonical_name(self, monkeypatch):
        monkeypatch.delenv("XUANDUN_PERSONAL_PORT", raising=False)
        monkeypatch.setenv("XUANDUN_PROXY_PORT", "19999")
        cfg = PersonalConfig()
        cfg.apply_env_overrides()
        assert cfg.server.port == 19999

    def test_python_accepts_legacy_name(self, monkeypatch):
        monkeypatch.delenv("XUANDUN_PROXY_PORT", raising=False)
        monkeypatch.setenv("XUANDUN_PERSONAL_PORT", "19998")
        cfg = PersonalConfig()
        cfg.apply_env_overrides()
        assert cfg.server.port == 19998

    def test_canonical_wins_over_legacy(self, monkeypatch):
        """两个都设了时以规范名为准 —— 不能靠字典顺序碰运气。"""
        monkeypatch.setenv("XUANDUN_PROXY_PORT", "19997")
        monkeypatch.setenv("XUANDUN_PERSONAL_PORT", "19996")
        cfg = PersonalConfig()
        cfg.apply_env_overrides()
        assert cfg.server.port == 19997

    def test_rust_accepts_both_names(self):
        """Rust 侧同样要认两个名字，否则兼容只是单向的。"""
        src = LIB_RS.read_text(encoding="utf-8")
        assert "XUANDUN_PROXY_PORT" in src
        assert "XUANDUN_PERSONAL_PORT" in src, (
            "Rust 侧不认历史变量名 —— 只改一侧等于把「静默失效」留给另一半用户"
        )


# ══════════════════════════════════════════════════════════════
# P1-10：三套超时必须严格递增
# ══════════════════════════════════════════════════════════════


class TestTimeoutChainIsOrdered:
    """引擎内部预算 < 桌面端 < 前端。

    ★ 为什么必须有序：任何一层比上一层小时，客户端先放弃、服务端还在
      发请求 —— 界面报超时，日志里却有一次正常的探测结论，两边对不上。
    """

    def test_budget_order(self):
        import re

        from daoti_xuandun_personal.proxy import app as app_mod

        engine_budget = app_mod.PROBE_TOTAL_BUDGET_S

        rust = LIB_RS.read_text(encoding="utf-8")
        m = re.search(r"const REQ_PROBE: Duration = Duration::from_secs\((\d+)\);", rust)
        assert m, "找不到 Rust 侧 REQ_PROBE 定义"
        rust_probe = int(m.group(1))

        ts = API_TS.read_text(encoding="utf-8")
        m2 = re.search(r"PROBE:\s*(\d+)_000", ts)
        assert m2, "找不到前端 TIMEOUT.PROBE 定义"
        ts_probe = int(m2.group(1))

        assert engine_budget < rust_probe, (
            f"引擎预算 {engine_budget}s ≥ 桌面端 {rust_probe}s —— "
            "桌面端会先超时，而引擎还在探测"
        )
        assert rust_probe < ts_probe, (
            f"桌面端 {rust_probe}s ≥ 前端 {ts_probe}s —— 浏览器通道会先超时"
        )

    def test_engine_budget_matches_its_own_constants(self):
        from daoti_xuandun_personal.proxy import app as app_mod

        expected = int(
            app_mod.PROBE_MAX_ROUNDS
            * (app_mod.PROBE_CONNECT_TIMEOUT_S + app_mod.PROBE_READ_TIMEOUT_S)
        )
        assert app_mod.PROBE_TOTAL_BUDGET_S == expected
        assert app_mod.PROBE_MAX_ROUNDS == 2, (
            "test_relay 最多打两次探针 —— 轮数改了这条预算必须跟着改"
        )


# ══════════════════════════════════════════════════════════════
# P1-11：错误体三种形态都要能取出人话
# ══════════════════════════════════════════════════════════════


class TestErrorBodyShapes:
    def test_frontend_knows_all_three_shapes(self):
        src = API_TS.read_text(encoding="utf-8")
        assert "extractErrorMessage" in src
        start = src.index("function extractErrorMessage")
        body = src[start:src.index("\n}\n", start)]
        for key in ("detail", "error", "message", "msg"):
            assert key in body, f"前端未处理错误体字段 {key}"

    def test_rust_knows_all_three_shapes(self):
        src = LIB_RS.read_text(encoding="utf-8")
        assert "fn extract_error_message" in src
        start = src.index("fn extract_error_message")
        body = src[start:src.index("\n}\n", start)]
        for key in ("detail", "error", "message", "msg"):
            assert key in body, f"Rust 未处理错误体字段 {key}"


# ══════════════════════════════════════════════════════════════
# P1-12：/api/relays 必须带 level
# ══════════════════════════════════════════════════════════════


class TestRelayLevelIsExposed:
    def test_to_dict_contains_level(self):
        rep = RelayReputation(domain="r.example.invalid", score=90)
        d = rep.to_dict()
        assert d["level"] == "safe", (
            "level 是 @property，不进 asdict —— 响应里没有它，"
            "首页信誉等级文字永远是空"
        )

    def test_level_follows_score(self):
        assert RelayReputation(score=30).to_dict()["level"] == "risky"
        assert RelayReputation(score=60).to_dict()["level"] == "normal"
        assert RelayReputation(score=100, known_malicious=True).to_dict()[
            "level"
        ] == "malicious"


# ══════════════════════════════════════════════════════════════
# P1-13~18：交互异常路径（前端无法在 pytest 内执行，锁「失败时的行为」）
# ══════════════════════════════════════════════════════════════

LOGS_TSX = ROOT / "desktop" / "src" / "pages" / "Logs.tsx"
SETTINGS_TSX = ROOT / "desktop" / "src" / "pages" / "Settings.tsx"
ONBOARDING_TSX = ROOT / "desktop" / "src" / "pages" / "Onboarding.tsx"
UPDATER_TS = ROOT / "desktop" / "src" / "lib" / "updater.ts"


def _read(p: Path) -> str:
    return p.read_text(encoding="utf-8")


class TestLoadFailureIsNotAnEmptyState:
    """P1-13：加载失败与「暂无记录」必须是两种不同的画面。

    两者同屏时，用户读到的是「日志没了」—— 而事实是这次没取到。
    """

    def test_empty_card_is_suppressed_on_error(self):
        src = _read(LOGS_TSX)
        assert "loadErr ? null" in src, (
            "加载失败时仍会渲染「暂无日志记录」空态，用户会把「取不到」读成「没有」"
        )


class TestClearAllIsLockedInFlight:
    """P1-14：「清空」是唯一没有在飞锁的破坏性按钮。"""

    def test_handler_guards_and_releases(self):
        src = _read(LOGS_TSX)
        assert "const [clearing, setClearing]" in src
        start = src.index("const handleClearAll")
        body = src[start:start + 1200]
        assert "if (clearing) return;" in body, "清空没有在飞锁，可重复确认"
        assert "setClearing(false)" in body, "清空失败后锁不释放，按钮永久不可用"

    def test_button_is_disabled_while_clearing(self):
        src = _read(LOGS_TSX)
        i = src.index("onClick={handleClearAll}")
        snippet = src[i:i + 400]
        assert "clearing" in snippet.split("/>")[0], "清空按钮未随在飞状态禁用"


class TestEvidenceFailureIsDistinguishable:
    """P1-15：证据包取不到，与「这条没有凭证来源」必须分开表达。"""

    def test_evidence_error_state_and_retry(self):
        src = _read(LOGS_TSX)
        assert "setEvidenceError(" in src, "证据包失败被 catch 吞掉，界面无从区分"
        assert "证据包加载失败" in src, "失败态没有面向用户的说明"
        assert "setEvidenceRetry" in src, "失败后没有重试入口"


class TestDrawerDoesNotRefetchOnParentRender:
    """P1-16：抽屉 effect 依赖内联 onClose 会导致每次父组件重渲染都闪回加载中。"""

    def test_onclose_is_held_in_ref(self):
        src = _read(LOGS_TSX)
        assert "onCloseRef" in src, "onClose 仍直接进依赖，父组件重渲染会重打接口"
        assert "[logId, onClose, toast]" not in src, (
            "详情 effect 仍依赖 onClose —— 抽屉会闪回「加载中」并重复请求"
        )


class TestStatusRequestsHaveFailureStates:
    """P1-17：设置页引擎状态 / 向导机器码在失败时不能永远停在「读取中」。"""

    def test_settings_engine_status_failure(self):
        src = _read(SETTINGS_TSX)
        assert "setEngineError(" in src
        assert "读取失败" in src, "引擎状态失败时仍显示「读取中…」，且无重试"

    def test_onboarding_machine_code_failure(self):
        src = _read(ONBOARDING_TSX)
        assert "setLicenseError(" in src
        assert "获取失败" in src, "机器码失败时仍显示「正在获取…」，且无重试"


class TestUpdateInstallCannotHangForever:
    """P1-18：更新安装必须有超时，且成功/失败都要释放锁。"""

    def test_watchdog_exists(self):
        src = _read(UPDATER_TS)
        assert "UPDATE_STALL_TIMEOUT_MS" in src, "下载无超时，可能永久停在某个百分比"
        assert "Promise.race" in src, "看门狗未接入下载流程"

    def test_lock_released_on_success_path(self):
        src = _read(SETTINGS_TSX)
        start = src.index("const handleInstallUpdate")
        body = src[start:start + 1500]
        assert "finally" in body and "setUpdateBusy(false)" in body, (
            "成功路径不释放锁 —— 重启命令不返回时界面永久停在「下载安装中」"
        )


# ══════════════════════════════════════════════════════════════
# P1-19~26：发布链
# ══════════════════════════════════════════════════════════════

import importlib.util  # noqa: E402
import re  # noqa: E402

CI_YML = ROOT / ".github" / "workflows" / "ci.yml"
RELEASE_YML = ROOT / ".github" / "workflows" / "release.yml"
BUILD_ENGINE = ROOT / "desktop" / "build_engine.py"
CHECK_SIGNING = ROOT / ".github" / "scripts" / "check_signing_key.py"
SCAN_SECRETS = ROOT / ".github" / "scripts" / "scan_secrets.py"


def _action_refs(path: Path) -> list[str]:
    return re.findall(r"uses:\s*([^\s#]+)", _read(path))


def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


class TestActionsArePinned:
    """P1-19：action 必须钉 40 位 commit SHA。

    tag 与分支都能被移动，`@v5` 等于把构建交给上游随时改写 ——
    release.yml 早已全部钉死，ci.yml 却还是浮动 tag，两条流水线不一致。
    """

    def test_both_workflows_pin_full_sha(self):
        for wf in (CI_YML, RELEASE_YML):
            refs = _action_refs(wf)
            assert refs, f"{wf.name} 里没有找到任何 action"
            for ref in refs:
                if ref.startswith("./"):
                    continue
                owner_repo, _, sha = ref.partition("@")
                assert re.fullmatch(r"[0-9a-f]{40}", sha), (
                    f"{wf.name} 里的 {ref} 未钉 40 位 SHA —— "
                    "浮动 tag 可被上游移动，等于构建结果不可复现"
                )


class TestGovernanceFilesExist:
    """P1-20：公开仓库必须有安全策略、代码所有者、PR 模板、依赖更新。"""

    def test_files_present(self):
        for rel in (
            "SECURITY.md",
            ".github/CODEOWNERS",
            ".github/dependabot.yml",
            ".github/pull_request_template.md",
        ):
            p = ROOT / rel
            assert p.is_file(), f"缺少治理文件 {rel}"
            assert p.stat().st_size > 100, f"{rel} 是空壳"

    def test_codeowners_paths_exist(self):
        """CODEOWNERS 里写错路径不会报错，只会静默不生效。"""
        for line in _read(ROOT / ".github" / "CODEOWNERS").splitlines():
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            pattern = s.split()[0]
            if pattern == "*":
                continue
            assert (ROOT / pattern.lstrip("/")).exists(), (
                f"CODEOWNERS 指向不存在的路径：{pattern}"
            )


class TestProvenanceAndChecksumCoverage:
    """P1-21 / P1-22：来源证明，以及校验和要覆盖真正决定更新的那些文件。"""

    def test_provenance_attested_and_read_back(self):
        src = _read(RELEASE_YML)
        assert "attest-build-provenance@" in src, "没有生成 SLSA 来源证明"
        assert "gh attestation verify" in src, (
            "只写证明不回读 —— 「上传成功」不等于「能验证通过」"
        )
        m = re.search(r"attest-build-provenance@([0-9a-f]{40})", src)
        assert m, "来源证明的 action 未钉 40 位 SHA"

    def test_checksums_cover_manifest_and_signatures(self):
        src = _read(RELEASE_YML)
        # 清单必须先于校验和生成，否则 latest.json 永远没有校验值
        assert src.index("Generate updater manifest") < src.index(
            "Generate SHA256 checksums"
        ), "latest.json 在校验和之后生成，它因此不可能被覆盖"
        start = src.index("Generate SHA256 checksums")
        body = src[start:start + 2000]
        assert "latest\\.json" in body, "校验和未显式断言覆盖 latest.json"
        assert "\\.sig" in body, "校验和未显式断言覆盖 .sig"
        assert "RELEASE_NOTES.md" in body, "发布说明没有被计入校验范围"


class TestSigningSecretsDoNotLeakIntoArgv:
    """P1-23：口令不得经 shell 拼接或命令行 argv 传递。"""

    def test_check_signing_key_has_no_shell(self):
        src = _read(CHECK_SIGNING)
        assert "shell=True" not in src, (
            "签名探测仍在用 shell 拼命令 —— 口令会进 argv，且可被引号注入"
        )
        assert '"-p"' not in src and "'-p'" not in src, (
            "口令仍以 -p 参数传入；CLI 已支持环境变量，没必要进命令行"
        )

    def test_release_masks_cert_password(self):
        src = _read(RELEASE_YML)
        assert "::add-mask::$CERT_PASSWORD" in src
        assert 'SIGN_PWD="$CERT_PASSWORD"' in src, (
            "口令仍经 argv 传给生成签名配置的 python"
        )

    def test_signing_material_cleanup_is_unconditional(self):
        src = _read(RELEASE_YML)
        assert "Cleanup signing material" in src
        start = src.index("Cleanup signing material")
        assert "always()" in src[start:start + 200], (
            "清理依赖前一步成功 —— 校验失败时临时证书会留在 runner 上"
        )


class TestPrivateKeyGateIsContentBased:
    """P1-24：只按文件名 grep private 会漏掉 id_rsa / *.p12 / 粘进文档的 PEM。"""

    def test_detects_pem_header_in_text(self):
        mod = _load_module(SCAN_SECRETS, "scan_secrets_probe")
        # ★ 头部必须拼出来：本机玄盾会把"像私钥"的字面量替换成占位符
        header = ("-----BEGIN " + "RSA " + "PRIVATE" + " KEY" + "-----").encode()
        assert mod.scan_bytes("notes.md", header + b"\nAAAA\n"), (
            "PEM 私钥粘进文本文件时未被检出"
        )

    def test_detects_ssh_private_key_by_name(self):
        mod = _load_module(SCAN_SECRETS, "scan_secrets_probe2")
        assert mod.scan_bytes("id_rsa", b"dummy")

    def test_clean_text_passes(self):
        mod = _load_module(SCAN_SECRETS, "scan_secrets_probe3")
        assert not mod.scan_bytes("README.md", b"hello world")

    def test_repository_is_clean(self):
        mod = _load_module(SCAN_SECRETS, "scan_secrets_probe4")
        assert mod.main([]) == 0


class TestReleaseCannotSilentlyOverwrite:
    """P1-25：tag 被移动后重跑会静默替换已发布资产。"""

    def test_release_guard_and_environment(self):
        src = _read(RELEASE_YML)
        assert "environment: release" in src, "发布没有挂 environment，缺少审核闸门"
        assert "Refuse to overwrite" in src, "没有阻止「重复发布同名 Release」"


class TestBuildDoesNotSilentlyDownload:
    """P1-26：构建期不得静默从第三方拉工具。"""

    def test_no_assume_yes_for_download(self):
        src = _read(BUILD_ENGINE)
        assert "--assume-yes-for-download" not in src, (
            "Nuitka 仍会自动确认下载 —— 构建期会静默抓取第三方可执行文件"
        )


# ══════════════════════════════════════════════════════════════
# P1-27~29：仓库对外暴露面
# ══════════════════════════════════════════════════════════════


class TestRepositorySurface:
    """P1-27 / P1-29：该随仓库走的文档要在，不该在的要出库。

    这两条都是"看代码看不出来、只有 clone 一次才知道"的问题：
    架构文档不在仓库里，clone 下来的人只能靠猜；
    另一款产品的使用指南在仓库里，Release 里就会混进别的版本号。
    """

    def test_architecture_docs_are_shipped(self):
        ignore = _read(ROOT / ".gitignore")
        for name in ("README.md", "ARCHITECTURE.md", "DEVELOPMENT.md",
                     "SECURITY_BOUNDARIES.md"):
            assert (ROOT / "docs" / name).is_file(), f"docs/{name} 不存在"
            assert f"!docs/{name}" in ignore, (
                f"docs/{name} 仍被 .gitignore 排除 —— clone 后拿不到"
            )

    def test_enterprise_doc_is_out_of_the_repo(self):
        import subprocess

        out = subprocess.run(
            ["git", "ls-files", "企业版文档"],
            cwd=str(ROOT), capture_output=True, text=True,
        ).stdout.strip()
        assert out == "", f"企业版文档仍被追踪：{out}"
        assert "企业版文档/" in _read(ROOT / ".gitignore"), (
            "企业版文档未加入忽略列表，下次很容易被重新 git add 回来"
        )


# ══════════════════════════════════════════════════════════════
# P1-26 补完 / P1-30：构建出网收紧 + 本地代理不可用时的恢复指引
# ══════════════════════════════════════════════════════════════


class TestBuildJobEgressIsEnforced:
    """构建 job 的出网必须**默认拒绝**。

    audit 只记录不拦截：被投毒的依赖可以在构建期把载荷或数据发出去，
    而所有门禁照样全绿。允许清单必须覆盖真实依赖，否则会以假阳性阻断发布。
    """

    def _build_steps(self) -> str:
        src = _read(RELEASE_YML)
        start = src.index("name: Build (${{ matrix.art }})")
        end = src.index("Upload artifacts", start)
        return src[start:end]

    def test_egress_policy_is_block_with_allowlist(self):
        body = self._build_steps()
        assert "egress-policy: block" in body, (
            "构建 job 仍在 audit —— 出网不拦截等于供应链加固空转"
        )
        assert "allowed-endpoints" in body, "block 却没有允许清单，构建必挂"

    def test_allowlist_covers_real_dependencies(self):
        body = self._build_steps()
        required = (
            "github.com:443",            # 取源码 / 工具链 / 打包工具
            "pypi.org:443",              # 引擎依赖
            "registry.npmjs.org:443",    # 前端依赖
            "index.crates.io:443",       # Rust 依赖
            "static.rust-lang.org:443",  # 工具链
            "archive.ubuntu.com:80",     # apt（Linux 打包库）
        )
        for host in required:
            assert host in body, f"允许清单缺少 {host}，发布会被假阳性阻断"


class TestLocalProxyOfflineIsRecoverable:
    """P1-30：引擎没起来时，用户必须能就地恢复。

    此前只写「请确认玄盾代理已启动（127.0.0.1:端口）」+「重试」——
    那是一句用户无法执行的指令：他不知道引擎是什么、怎么启动，
    也不知道「端口被别的程序占了」「改过端口没重启」这两种常见原因。
    """

    def test_shared_guide_offers_real_actions(self):
        src = _read(ROOT / "desktop" / "src" / "components" / "EngineOffline.tsx")
        assert "api.restartEngine()" in src, "引导里没有真正的恢复动作"
        assert "重启引擎" in src
        assert "/settings#sec-engine" in src, "没有通往「运行状态」的入口"
        # 三种最常见原因都要出现，否则用户仍然不知道从哪查
        assert "改过端口" in src and "占用" in src

    def test_landing_pages_use_the_shared_guide(self):
        for name in ("Dashboard.tsx", "Settings.tsx"):
            src = _read(ROOT / "desktop" / "src" / "pages" / name)
            assert "EngineOffline" in src, f"{name} 仍在自己拼一段无法执行的提示"

    def test_status_bar_offers_restart(self):
        src = _read(ROOT / "desktop" / "src" / "components" / "Layout.tsx")
        assert "handleRestartEngine" in src, "状态栏只报「本地代理未运行」，没有恢复入口"
        assert "restartEngine" in src
        assert "查看原因" in src

    def test_boot_has_a_time_deadline(self):
        """「还在启动」必须有时间上限。

        端口被别的程序占着时请求会挂着不回：既没有成功也没有异常，
        失败计数永远是 0 —— 只按次数判就会永远停在「首次启动需要几秒」。
        """
        comp = _read(ROOT / "desktop" / "src" / "components" / "EngineOffline.tsx")
        assert "BOOT_DEADLINE_MS" in comp
        for name in ("components/Layout.tsx", "pages/Dashboard.tsx"):
            src = _read(ROOT / "desktop" / "src" / name)
            assert "useBootDeadline" in src, f"{name} 没有时间兜底，可能永久停在「启动中」"

    def test_engine_down_is_not_mistaken_for_first_run(self):
        """取不到配置 ≠ 首次使用：不能把用户丢进向导。"""
        src = _read(ROOT / "desktop" / "src" / "App.tsx")
        start = src.index("const cfg = (await api.getConfig())")
        body = src[start:start + 800]
        assert "setNeedOnboarding(false)" in body, (
            "引擎没起来时仍会进首次向导 —— 用户填完中转站也保存不了"
        )
