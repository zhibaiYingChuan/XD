# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白

"""测试基座：**强制隔离用户的真实数据目录**。

★★ 2026-10-29（第三轮审查 P0-8）为什么要这个文件
────────────────────────────────────────────────────────────────
本轮审查实测到两类「只在别人机器上才能复现」的问题，根因相同：

1. `test_privacy_hardening` 的 fixture 只设了 `XUANDUN_DATA_DIR` 再
   `importlib.reload(paths)`，但 `config.CONFIG_FILE` 是 **import 时固化**
   的路径 —— 用例实际读到的是开发机真实的 `config.json`（连带真实中转站），
   于是 `/v1/chat/completions` 真的向那家发了请求并拿到上游 401：
   同一个用例单独跑绿、整文件跑红。

2. 部分夹具会往 `%LOCALAPPDATA%/com.daoti.xuandun-personal/` 写签发记录
   与日志。测试污染真实用户数据，等于「跑一次测试改一次配置」。

因此这里做一个 autouse 的隔离基座：每个用例都有独立数据目录，
`config.CONFIG_FILE` 一并指向它。用例不需要知道这件事，
也不会因为忘记隔离而互相踩。

★ 注意：本文件只改**路径**，不改任何业务逻辑；
  需要验证「读真实目录」的用例请显式 monkeypatch 回去。
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

# ★★★ 2026-11-13：把个人版 src 强制排到 sys.path 最前。
#
#   本机 site-packages 里有两条 editable 安装：
#     __editable__.daoti_xuandun-1.3.1.pth        → H:\XuanDun\src
#     __editable__.daoti_xuandun_personal-*.pth   → H:\XuanDun\personal\src
#   前者排在前面，于是 `import daoti_xuandun` 解析到**根目录那份旧副本**，
#   而实际打包（desktop/build_engine.py）用的是 personal\src 这份。
#
#   后果：本地跑测试全绿，发布包里却是旧判据。2026-11-13 的私钥误报
#   排查中，连「企业版一致性断言」都校验错了对象 —— 断言的对象是根目录
#   副本，改 personal 那份根本不在它的视野里。
#
#   这里在 conftest 阶段一次性把 personal\src 提到最前，
#   让所有测试（无论单独跑还是全量跑）都对准真正会被打包的那份。
_PERSONAL_SRC = Path(__file__).resolve().parents[1] / "src"
# ★ 2026-11-13：必须无条件置顶 —— editable .pth 已把
#   该路径加入 sys.path（位置在 H:\XuanDun\src 之后），
#   只判断 `not in` 会跳过，导致 import 到根目录旧副本。
if str(_PERSONAL_SRC) in sys.path:
    sys.path.remove(str(_PERSONAL_SRC))
sys.path.insert(0, str(_PERSONAL_SRC))

# 把可能已被导入的旧副本清掉，确保后续 import 走 personal\src
for _mod in [m for m in sys.modules if m == "daoti_xuandun" or m.startswith("daoti_xuandun.")]:
    sys.modules.pop(_mod, None)


@pytest.fixture(autouse=True)
def _isolate_user_data(tmp_path, monkeypatch):
    """把数据目录与配置文件路径都钉到本用例的临时目录。"""
    data_dir = tmp_path / "userdata"
    data_dir.mkdir(parents=True, exist_ok=True)

    monkeypatch.setenv("XUANDUN_DATA_DIR", str(data_dir))

    cfg_mod = importlib.import_module("daoti_xuandun_personal.config")
    monkeypatch.setattr(
        cfg_mod, "CONFIG_FILE", data_dir / "config.json", raising=False
    )

    yield
