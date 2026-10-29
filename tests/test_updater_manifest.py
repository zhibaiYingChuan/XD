# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白

"""自动更新清单（latest.json）生成的契约测试。

★ 这份清单决定了「旧版本能不能发现自己该升级」。
  它出错的方式非常安静：新版本照常发布，所有旧版本却永远
  检查不到更新，而界面上只会显示「已是最新版本」。
  所以必须把「缺签名 / 缺平台 / 非 tag」都变成显式失败。
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / ".github" / "scripts" / "make_latest_json.py"


def _seed(art: Path, *, exe=True, mac=True, linux=True, sig=True) -> None:
    files = {
        "win": ("玄盾_0.1.18-alpha_x64-setup.exe", "SIG_WIN"),
        "mac": ("玄盾.app.tar.gz", "SIG_MAC"),
        # ★ Linux 的更新包就是 AppImage 本身（Tauri 不产 .AppImage.tar.gz）
        "linux": ("玄盾_0.1.18-alpha_amd64.AppImage", "SIG_LINUX"),
    }
    for key, (name, signature) in files.items():
        enabled = {"win": exe, "mac": mac, "linux": linux}[key]
        if not enabled:
            continue
        d = art / key
        d.mkdir(parents=True)
        (d / name).write_text("fake", encoding="utf-8")
        if sig:
            (d / f"{name}.sig").write_text(signature, encoding="utf-8")


def _run(art: Path, tag: str = "v0.1.18-alpha"):
    env = {
        **os.environ,
        "GITHUB_REF_NAME": tag,
        "GITHUB_REPOSITORY": "zhibaiYingChuan/XD",
    }
    return subprocess.run(
        [sys.executable, str(SCRIPT), str(art)],
        capture_output=True, text=True, env=env,
    )


def test_all_platforms_are_listed(tmp_path):
    _seed(tmp_path)
    r = _run(tmp_path)
    assert r.returncode == 0, r.stderr
    data = json.loads((tmp_path / "latest.json").read_text(encoding="utf-8"))
    assert data["version"], "缺少版本号"
    assert data["pub_date"].endswith("Z")
    assert set(data["platforms"]) == {
        "windows-x86_64", "darwin-aarch64", "linux-x86_64",
    }
    win = data["platforms"]["windows-x86_64"]
    assert win["signature"] == "SIG_WIN", "签名被破坏（BOM/换行）"
    # 中文文件名必须被百分号编码，否则前端下载 404
    assert "%" in win["url"] and " " not in win["url"]

    # Linux 必须指向 AppImage 本体：写成 tar.gz 会 404（CI 根本不产它）
    linux = data["platforms"]["linux-x86_64"]
    assert linux["url"].endswith(".AppImage"), (
        f"Linux 更新包应指向 .AppImage，实际是 {linux['url']}"
    )
    assert linux["signature"] == "SIG_LINUX"


def test_missing_signature_is_fatal(tmp_path):
    _seed(tmp_path, sig=False)
    r = _run(tmp_path)
    assert r.returncode != 0, "缺 .sig 却生成成功 —— 更新包无法验签"
    assert ".sig" in (r.stderr + r.stdout)


def test_missing_windows_bundle_is_fatal(tmp_path):
    _seed(tmp_path, exe=False)
    r = _run(tmp_path)
    assert r.returncode != 0
    assert "Windows" in (r.stderr + r.stdout)


def test_missing_macos_bundle_is_fatal(tmp_path):
    _seed(tmp_path, mac=False)
    r = _run(tmp_path)
    assert r.returncode != 0
    assert "macOS" in (r.stderr + r.stdout)


def test_missing_linux_is_tolerated(tmp_path):
    """AppImage 是可选产物（linuxdeploy 可能失败），缺失不应阻断发布。"""
    _seed(tmp_path, linux=False)
    r = _run(tmp_path)
    assert r.returncode == 0, r.stderr
    data = json.loads((tmp_path / "latest.json").read_text(encoding="utf-8"))
    assert "linux-x86_64" not in data["platforms"]
    assert "AppImage" in r.stderr, "缺失应留下 warning，而不是静默"


def test_non_tag_ref_is_rejected(tmp_path):
    _seed(tmp_path)
    r = _run(tmp_path, tag="main")
    assert r.returncode != 0, "非 tag 构建却生成了更新清单"


# ══════════════════════════════════════════════════════════════
# 配置与发布链路的结构判据
# ══════════════════════════════════════════════════════════════


def test_tauri_config_enables_updater_artifacts_for_every_platform():
    """公钥与端点必须在；`createUpdaterArtifacts` 也必须开启。

    ★ 2026-10-29 改判据：此前它只允许出现在 CI 配置里，
      理由是「本地没私钥，写进主配置会让 `tauri build` 直接失败」。
      但实测代价是 Linux AppImage **不产出** `.AppImage.tar.gz` ——
      更新清单里于是永远没有 `linux-x86_64`，Linux 用户永远收不到更新，
      而流水线一路绿。这不是「本地便不便利」能换的东西。
      现在主配置开启、本地构建需注入签名私钥（docs/DEVELOPMENT.md 已写明）。
    """
    conf = json.loads(
        (REPO / "desktop/src-tauri/tauri.conf.json").read_text(encoding="utf-8")
    )
    updater = conf["plugins"]["updater"]
    assert updater["pubkey"].strip(), "更新公钥为空 —— 客户端无法验签"
    assert any(
        "releases/latest/download/latest.json" in e
        for e in updater["endpoints"]
    ), "更新端点不是 releases/latest，指针会失效"
    assert conf["bundle"].get("createUpdaterArtifacts") is True, (
        "主配置没开 createUpdaterArtifacts —— Linux 不会产出 .AppImage.tar.gz，"
        "latest.json 里也就永远没有 linux-x86_64"
    )

    # CI 叠加的同值配置保留：它让「CI 要产出更新签名包」在流水线里可见。
    ci_conf = json.loads(
        (REPO / "desktop/src-tauri/tauri.updater.conf.json")
        .read_text(encoding="utf-8")
    )
    assert ci_conf["bundle"]["createUpdaterArtifacts"] is True

    # 本地构建的代价必须写在文档里，否则下一个人本地打包会撞墙。
    dev = (REPO / "docs" / "DEVELOPMENT.md").read_text(encoding="utf-8")
    assert "本地构建需注入签名私钥" in dev


def test_release_workflow_signs_and_publishes_manifest():
    text = (REPO / ".github" / "workflows" / "release.yml").read_text(
        encoding="utf-8"
    )
    for needle in (
        "tauri.updater.conf.json",       # 只在 CI 产出签名包
        "TAURI_SIGNING_PRIVATE_KEY",     # 签名私钥
        "check_signing_key.py",          # 私钥/公钥错配门禁
        "make_latest_json.py",           # 生成更新清单
        "latest.json",                   # 作为 Release 资产
        "*.sig",                         # 上传签名文件
        "Stage release assets with ASCII names",  # ASCII 资产名
        "make_latest_json.py dist",      # 清单与实际上传名同源
    ):
        assert needle in text, f"release.yml 缺少 {needle}"

    # ★ 2026-10-21 线上真实事故：GitHub 会把资产名里的中文剥掉，
    #   而清单写的是原名 → 更新 URL 404。不能再让 tar.gz 通配把
    #   deb 打包临时文件也带进发布。
    assert "artifacts/**/*.tar.gz" not in text, (
        "发布资产用了 tar.gz 通配 —— 会把 deb 的 control/data.tar.gz 也发出去"
    )
    assert "**/*.app.tar.gz" in text, "macOS 更新包应只收 *.app.tar.gz"

    # ★ 2026-10-29：Linux 的更新包是 `.AppImage.tar.gz`（大写 A、大写 I），
    #   与 macOS 的 `*.app.tar.gz` 互不覆盖 —— 上传与改名两处都必须显式写上。
    #   少了任何一处，更新包都会在到达 release job 之前被丢掉。
    assert "**/*.AppImage.tar.gz" in text, (
        "上传清单少了 .AppImage.tar.gz —— Linux 更新包走不到 release job"
    )
    assert "*.AppImage.tar.gz.sig)" in text, "改名分支缺 .AppImage.tar.gz.sig"
    assert "*.AppImage.tar.gz)" in text, "改名分支缺 .AppImage.tar.gz"

    # ★ 版本号必须从 Cargo.toml（SSOT）读，不能硬编码或用 tag 名 ——
    #   否则资产名与 latest.json 的 version 可能来自两个不同的地方。
    stage = text.split("Stage release assets with ASCII names", 1)[1]
    assert "desktop/src-tauri/Cargo.toml" in stage, (
        "ASCII 改名步骤没从 Cargo.toml 读版本号"
    )
    assert "${GITHUB_REF_NAME#v}" not in stage.split("ls -l dist", 1)[0], (
        "ASCII 改名步骤仍用 tag 名当版本号"
    )


# ══════════════════════════════════════════════════════════════
# 发布资产门禁（check_release_assets.py）的三条分支
# ══════════════════════════════════════════════════════════════

ASSET_GATE = REPO / ".github" / "scripts" / "check_release_assets.py"


def _seed_dist(d: Path, *, appimage: bool = True, update: bool = True,
               sig: bool = True) -> None:
    d.mkdir(parents=True, exist_ok=True)
    for name in (
        "xuandun-personal_0.1.27-alpha_x64-setup.exe",
        "xuandun-personal_0.1.27-alpha_aarch64.dmg",
        "xuandun-personal_0.1.27-alpha_aarch64.app.tar.gz",
        "xuandun-personal_0.1.27-alpha_amd64.deb",
    ):
        (d / name).write_text("x", encoding="utf-8")
    if not appimage:
        return
    base = "xuandun-personal_0.1.27-alpha_amd64.AppImage"
    (d / base).write_text("x", encoding="utf-8")
    if update:
        (d / f"{base}.tar.gz").write_text("x", encoding="utf-8")
    if sig:
        (d / f"{base}.sig").write_text("SIG", encoding="utf-8")


def _run_gate(d: Path, *, exempt: bool, notice: Path):
    env = {k: v for k, v in os.environ.items() if k != "ALLOW_MISSING_APPIMAGE"}
    if exempt:
        env["ALLOW_MISSING_APPIMAGE"] = "1"
    return subprocess.run(
        [sys.executable, str(ASSET_GATE), str(d), "--notice-out", str(notice)],
        capture_output=True, text=True, env=env,
    )


def test_asset_gate_passes_when_appimage_update_package_is_complete(tmp_path):
    """AppImage + 更新包 + 签名齐全 → 放行，且不写豁免提示。"""
    dist = tmp_path / "dist"
    _seed_dist(dist)
    notice = tmp_path / "notice.md"
    r = _run_gate(dist, exempt=False, notice=notice)
    assert r.returncode == 0, r.stdout + r.stderr
    assert not notice.exists(), "全都齐了却写了缺件提示"


def test_asset_gate_blocks_when_appimage_update_package_is_missing(tmp_path):
    """安装包在、更新包不在 → 未豁免必须 exit 1。

    ★ 这是最难被发现的缺件形态：Release 上「Linux 有包」，
      只有自动更新是哑的。旧门禁只查 .AppImage，因此一路放行。
    """
    dist = tmp_path / "dist"
    _seed_dist(dist, update=False)
    r = _run_gate(dist, exempt=False, notice=tmp_path / "notice.md")
    assert r.returncode == 1, r.stdout + r.stderr
    assert "AppImage.tar.gz" in (r.stdout + r.stderr), "没指出缺的到底是哪个包"


def test_asset_gate_allows_exempted_incomplete_appimage_with_notice(tmp_path):
    """已豁免 → 放行，但必须写出正文提示（缺件不能被静默吞掉）。"""
    dist = tmp_path / "dist"
    _seed_dist(dist, update=False)
    notice = tmp_path / "notice.md"
    r = _run_gate(dist, exempt=True, notice=notice)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "::warning" in r.stdout
    text = notice.read_text(encoding="utf-8")
    assert "更新包" in text and "自动更新" in text


def test_signature_parser_accepts_all_cli_output_shapes(tmp_path):
    """发版门禁的解析器必须兼容 CLI 的三种输出形态。

    ★ 2026-10-21 实测：CI 上 `tauri signer sign` 产出的 `.sig`
      只有一个 base64 行，而原解析器硬取第 2 行 → 报「格式异常」，
      把一个探测脚本的假设变成了发版阻断。
    """
    import base64
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "check_signing_key", REPO / ".github" / "scripts" / "check_signing_key.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    blob = b"Ed" + b"KEYID123" + b"\x00" * 64
    b64 = base64.b64encode(blob).decode()

    # ① 完整 minisign 块（4 行）
    full = tmp_path / "full.sig"
    full.write_text(
        "untrusted comment: signature from tauri secret key\n"
        + b64 + "\n"
        + "trusted comment: timestamp:1\tfile:x\n"
        + base64.b64encode(b"\x01" * 64).decode() + "\n",
        encoding="utf-8",
    )
    assert mod._extract_signature_blob("", full) == blob

    # ② 单行 base64
    single = tmp_path / "single.sig"
    single.write_text(b64 + "\n", encoding="utf-8")
    assert mod._extract_signature_blob("", single) == blob

    # ③ 只打到 stdout
    assert mod._extract_signature_blob(
        "untrusted comment: x\n" + b64 + "\n", tmp_path / "none.sig"
    ) == blob

    # ④ stdout 里把整个 .sig 内容又 base64 了一层（2026-10-21 真实踩到）
    #    —— 这层"套娃"解码后是一段文本，长度也 >74，
    #    绝不能被当成签名，否则 key id 会被读成 ASCII 的 "trusted "
    nested = base64.b64encode(
        ("untrusted comment: signature from tauri secret key\n" + b64 + "\n").encode()
    ).decode()
    assert mod._extract_signature_blob(
        nested + "\n" + b64 + "\n", tmp_path / "none2.sig"
    ) == blob

    # ⑤ tauri-cli 2.11.5 的真实形态：`.sig` 只有一行，
    #    是「整个 minisign 签名文件」的 base64（外层解开还有 4 行）
    real = tmp_path / "real.sig"
    real.write_text(
        base64.b64encode(
            (
                "untrusted comment: signature from tauri secret key\n"
                + b64 + "\n"
                + "trusted comment: timestamp:1\tfile:x\n"
                + base64.b64encode(b"\x02" * 64).decode() + "\n"
            ).encode()
        ).decode()
        + "\n",
        encoding="utf-8",
    )
    assert mod._extract_signature_blob("", real) == blob

    # ⑥ 签名二进制里恰好含 0x0A 也必须认（约 1/4 概率），
    #    曾经用「含换行就当文本」判断，把真签名整条丢掉
    lucky = b"Ed" + b"KEYID123" + b"\x0a" + b"\x00" * 63
    lucky_sig = tmp_path / "lucky.sig"
    lucky_sig.write_text(base64.b64encode(lucky).decode() + "\n", encoding="utf-8")
    assert mod._extract_signature_blob("", lucky_sig) == lucky
