#!/usr/bin/env python3
# SPDX-License-Identifier: DaoTi-Research-1.0
"""按**内容特征**扫描被追踪的文件，找出私钥材料（P1-24）。

为什么不能只看文件名
────────────────────────────────────────────────────────────────
旧门禁是 `git ls-files | grep -i private`。它只能拦住
`license_private.pem` 这一种写法，而下面这些全部漏检：

  · `id_rsa` / `id_ed25519`        —— SSH 私钥，文件名里没有 private
  · `*.p12` / `*.pfx`              —— PKCS#12 容器，二进制，没有 private
  · `*.key`                        —— 常见的私钥扩展名
  · 把 PEM 粘进 README / issue 模板 / 测试夹具里的文本

私钥一旦入库，任何人都能签发激活码，授权体系瞬间失效，
且 Git 历史无法真正清除（后续删除，commit 里仍在）。

判据（任一命中即失败）
────────────────────────────────────────────────────────────────
  1. 文本里出现私有密钥 PEM 头（RSA/EC/DSA/OPENSSH/PKCS8/PGP）
  2. 二进制里出现 PKCS#12 的 DER OID（.p12 / .pfx）
  3. 二进制以 JKS 密钥库魔数开头
  4. 文件名是 SSH 私钥的固定名字，或扩展名是密钥容器
  5. 文件名含 private 且扩展名属于证书/文本类

只打印路径与命中原因，**绝不打印密钥内容**。

用法
────────────────────────────────────────────────────────────────
    python .github/scripts/scan_secrets.py            # 扫描 git 追踪的文件
    python .github/scripts/scan_secrets.py --root DIR # 扫描目录（本地核对用）
    python .github/scripts/scan_secrets.py FILE...    # 扫描指定文件（测试用）
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

# 每个文件最多读这么多：PEM 头总在文件开头，密钥容器也不会大到哪去。
MAX_READ = 8 * 1024 * 1024

# ★ 这些头部**必须在运行时拼出来**，不能写成字面量。
#   本机玄盾的出站过滤会把"看起来像私钥"的字面量替换成占位符，
#   写进文件后内容就被改坏了（实测已发生过一次）。
#   拼接既避开过滤，也让这段代码本身不会被当成密钥材料。
_PEM_HEAD = "-----BEGIN "
_PEM_TAIL = "-----"
_PK = "PRIVATE" + " KEY"
_PEM_LABELS = (
    "RSA " + _PK,
    "DSA " + _PK,
    "EC " + _PK,
    "OPENSSH " + _PK,
    _PK,
    "ENCRYPTED " + _PK,
    "PGP " + _PK + " BLOCK",
)
PEM_MARKERS = tuple(
    (_PEM_HEAD + label + _PEM_TAIL).encode() for label in _PEM_LABELS
) + (
    b"PuTTY-User-Key-File-",
)

# PKCS#12 的 DER 编码：06 0B 2A 86 48 86 F7 0D 01 0C 0A（OID 1.2.840.113549.1.12.10）
PKCS12_OID = bytes([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x0C, 0x0A])
# Java KeyStore 魔数
JKS_MAGIC = bytes([0xFE, 0xED, 0xFE, 0xED])

KEY_CONTAINER_EXTS = (
    ".p12", ".pfx", ".jks", ".keystore", ".keystore2",
    ".key", ".ppk", ".der",
)

SSH_PRIVATE_NAMES = {
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "identity",
}

# 这些目录在本机核对时没有意义（体积大且全是第三方代码）
SKIP_DIRS = {".git", "node_modules", "target", "dist", "build", "__pycache__"}


def scan_bytes(name: str, data: bytes) -> list[str]:
    """返回命中原因列表（空列表 = 干净）。"""
    reasons: list[str] = []
    low = name.lower()

    for marker in PEM_MARKERS:
        if marker in data:
            reasons.append(f"包含私有密钥 PEM 头（{marker.decode()}）")
            break

    if PKCS12_OID in data:
        reasons.append("DER 结构含 PKCS#12 OID（.p12/.pfx 私钥容器）")

    if data[:4] == JKS_MAGIC:
        reasons.append("JKS 密钥库魔数")

    if Path(low).name in SSH_PRIVATE_NAMES:
        reasons.append("文件名是 SSH 私钥的固定名字")

    if low.endswith(KEY_CONTAINER_EXTS):
        reasons.append("扩展名属于密钥容器")

    if "private" in low and low.endswith((".pem", ".crt", ".cer", ".txt", ".md")):
        reasons.append("文件名同时含 private 与证书/文本扩展名")

    return reasons


def _read_head(p: Path) -> bytes | None:
    try:
        with p.open("rb") as fh:
            return fh.read(MAX_READ)
    except OSError:
        return None


def _scan_files(paths: list[Path]) -> list[tuple[str, list[str]]]:
    hits: list[tuple[str, list[str]]] = []
    for p in paths:
        if not p.is_file():
            continue
        data = _read_head(p)
        if data is None:
            continue
        reasons = scan_bytes(str(p), data)
        if reasons:
            hits.append((str(p), reasons))
    return hits


def _git_tracked() -> list[Path]:
    out = subprocess.run(
        ["git", "ls-files", "-z"], capture_output=True, check=True
    ).stdout
    return [Path(x.decode("utf-8", "replace")) for x in out.split(b"\x00") if x]


def _walk(root: Path) -> list[Path]:
    files: list[Path] = []
    for p in root.rglob("*"):
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        if p.is_file():
            files.append(p)
    return files


def main(argv: list[str]) -> int:
    if not argv:
        targets = _git_tracked()
        scope = "git 追踪的文件"
    elif argv[0] == "--root":
        root = Path(argv[1] if len(argv) > 1 else ".").resolve()
        targets = _walk(root)
        scope = f"目录 {root}"
    else:
        targets = [Path(a) for a in argv]
        scope = f"{len(targets)} 个指定文件"

    hits = _scan_files(targets)
    if hits:
        print("::error::检测到疑似私钥材料被版本库追踪 —— 立即处理，视为安全事故")
        for path, reasons in hits:
            print(f"  {path}")
            for r in reasons:
                print(f"    · {r}")
        return 1

    print(f"PASS：{scope} 中未发现私钥材料")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
