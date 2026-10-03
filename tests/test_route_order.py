# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白

"""FastAPI 路由顺序：静态段必须注册在参数段之前。

★ 为什么要单独锁住（2026-10-03 实测踩过）
────────────────────────────────────────────────────────────────
新增 `/api/logs/stats` 后实测得到 **422 Unprocessable Entity**，
而端点代码、函数名、调用方全都没错。

根因：FastAPI 按**注册顺序**匹配路由。`/api/logs/{log_id}` 是路径参数，
它会贪婪地吃掉 `/api/logs/stats` 里的 `stats`，
尝试 `int("stats")` 失败 → 422。

★ 为什么这个 bug 极其难查
  ① 报错信息（422 参数格式错）与真实原因（路由被抢占）毫无关系；
  ② 端点明明存在、名字也对，看起来「像是 FastAPI 的问题」；
  ③ 单测若只用 TestClient 测**别的**端点，全绿；
  ④ 只有真正请求那个被抢占的路径才会暴露。

所以判据不能是「端点存在」，必须是**注册顺序** ——
即在源码里，静态路径段的出现位置必须早于同前缀的参数段。
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
APP_PY = REPO / "src" / "daoti_xuandun_personal" / "proxy" / "app.py"

if str(REPO / "src") not in sys.path:
    sys.path.insert(0, str(REPO / "src"))


def _route_order() -> list[tuple[int, str]]:
    """按出现顺序抽出所有 @app.<method>("/api/...") 的路径。"""
    src = APP_PY.read_text(encoding="utf-8")
    return [
        (m.start(), m.group(2))
        for m in re.finditer(
            r'@app\.(get|post|delete|put)\(\s*"(/api/[^"]*)"', src
        )
    ]


class TestStaticRouteBeforeParamRoute:
    """★ 核心：同前缀下静态段必须早于参数段。"""

    def test_logs_stats_before_log_id(self):
        """★ 本次实际踩到的那个。

        回归症状：/api/logs/stats 返回 422，
        而端点存在、名字正确、调用方也没错。
        """
        order = _route_order()
        stats_at = next(
            (i for i, (_, p) in enumerate(order) if p == "/api/logs/stats"),
            None,
        )
        param_at = next(
            (i for i, (_, p) in enumerate(order) if p == "/api/logs/{log_id}"),
            None,
        )
        assert stats_at is not None, "缺少 /api/logs/stats 路由"
        assert param_at is not None, "缺少 /api/logs/{log_id} 路由"
        assert stats_at < param_at, (
            "/api/logs/stats 注册在 /api/logs/{log_id} 之后 —— "
            "它会被参数路由吃掉并返回 422，"
            "而报错信息指向「参数格式错」，与真实原因无关"
        )

    def test_no_param_route_swallows_a_sibling_static_path(self):
        """★ 通用判据：扫全部路由，找被参数段遮蔽的静态路径。

        比逐对比较更可靠 —— 将来新增端点时自动纳入检查，
        不必记得补一条用例。
        """
        order = _route_order()
        violations: list[str] = []

        for i, (_, param_path) in enumerate(order):
            m = re.fullmatch(r"(/api/[^/]*)\{[^}]+\}(/.*)?", param_path)
            if not m:
                continue
            prefix = m.group(1)
            for j, (_, other) in enumerate(order):
                if j >= i:
                    continue        # 只看更早注册的
                # other 是该前缀下的静态兄弟，且不是参数路由自身
                if other.startswith(prefix) and "{" not in other:
                    # 段数相同才可能被贪婪吃掉
                    if len(other.split("/")) == len(param_path.split("/")):
                        violations.append(
                            f"{other}（第 {j} 段）注册在 "
                            f"{param_path}（第 {i} 段）之前，"
                            f"会被参数路由遮蔽"
                        )
        assert not violations, (
            "存在被参数路由遮蔽的静态路径：\n  " + "\n  ".join(violations)
        )

    def test_route_order_is_deterministic_at_runtime(self):
        """★ 运行时实证：直接问 FastAPI 路由表谁先注册。

        源码顺序判据是结构性的，但真正的权威是运行时注册表 ——
        若将来有人用 router.include_router 改变顺序，
        源码判据会误判为通过。这里从实际 app 对象取证。
        """
        from daoti_xuandun_personal.proxy.app import create_app

        app = create_app()
        paths = []
        for r in app.routes:
            path = getattr(r, "path", "")
            if path.startswith("/api/logs"):
                paths.append(path)

        assert "/api/logs/stats" in paths, (
            f"运行时路由表里没有 /api/logs/stats —— 现有：{paths}"
        )
        i_stats = paths.index("/api/logs/stats")
        i_param = paths.index("/api/logs/{log_id}")
        assert i_stats < i_param, (
            f"运行时注册顺序也不对：stats@{i_stats} 晚于 "
            f"{{log_id}}@{i_param} —— 源码已改但运行时未生效"
        )


class TestStatsEndpointWorks:
    """端点本身要真的能用（不只是存在）。"""

    def test_stats_returns_expected_shape(self, tmp_path, monkeypatch):
        """★ 用真实请求跑一遍，比断言「函数存在」有说服力。

        判据是「不是 422」：路由被参数段抢占时，症状恰好就是 422，
        而端点代码看起来完全正常。
        """
        monkeypatch.setenv("XUANDUN_DATA_DIR", str(tmp_path))
        import importlib
        import time

        from fastapi.testclient import TestClient

        from daoti_xuandun_personal import paths
        importlib.reload(paths)
        from daoti_xuandun_personal.proxy import app as app_mod

        try:
            # ★ 必须用 with：TestClient 只有在上下文里才跑 lifespan，
            #   否则 _storage 恒为 None，端点会返回 503「存储未就绪」——
            #   那是「引擎还没起」，不是路由问题，两者必须分开判。
            with TestClient(app_mod.create_app()) as client:
                r = client.get("/api/logs/stats")
                assert r.status_code != 422, (
                    "/api/logs/stats 返回 422 —— "
                    "它被 /api/logs/{log_id} 抢占了（注册顺序错误）"
                )
                assert r.status_code == 200, (
                    f"/api/logs/stats 返回 {r.status_code}：{r.text[:200]}"
                )
                body = r.json()
                for key in ("total", "marked_safe", "by_type", "by_action",
                            "top_domains", "oldest_ts", "newest_ts"):
                    assert key in body, f"响应缺字段 {key}：{body}"
                assert isinstance(body["total"], int)
                assert isinstance(body["by_type"], dict)
        finally:
            monkeypatch.delenv("XUANDUN_DATA_DIR", raising=False)
            importlib.reload(paths)