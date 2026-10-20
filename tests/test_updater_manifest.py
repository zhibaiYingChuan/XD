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


def test_tauri_config_enables_updater_but_not_local_signing():
    """公钥与端点必须在；但 createUpdaterArtifacts 只能在 CI 配置里。

    ★ 若把 createUpdaterArtifacts 写进主配置，本地 `tauri build`
      会因为缺少 TAURI_SIGNING_PRIVATE_KEY 直接失败 ——
      这是「为了发版而把日常构建弄坏」。
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
    assert "createUpdaterArtifacts" not in conf["bundle"], (
        "主配置开启了 updater 产物 —— 本地构建会被要求提供签名私钥"
    )

    ci_conf = json.loads(
        (REPO / "desktop/src-tauri/tauri.updater.conf.json")
        .read_text(encoding="utf-8")
    )
    assert ci_conf["bundle"]["createUpdaterArtifacts"] is True


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
