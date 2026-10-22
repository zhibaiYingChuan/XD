# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白
# 本文件受道体研究许可证 v1.0 约束，禁止逆向工程和再分发
# 详见 LICENSE 文件

"""按中转站分配的额外入口端口。

为什么需要这一层（2026-10-22）
────────────────────────────────────────────────────────────
多数 AI 工具（尤其是 IDE 插件）按「服务地址」区分供应商，
同一个地址只允许填一次。用户同时用两家中转站时，
两家的模型 ID 往往一模一样（都是 gpt-4o / claude-sonnet），
工具里根本加不进第二条 —— 换 Key 也不行，因为它只认地址。

于是给每家中转站一个**专属端口**：
    A 家 → http://127.0.0.1:18801/v1
    B 家 → http://127.0.0.1:18802/v1
地址天然不同，两家可以并存；端口本身决定了请求发给谁。

设计约束
────────────────────────────────────────────────────────────
1. **主端口行为一字不改**：主端口仍按 Key 识别、识别不到用当前启用项。
   专属端口只是多开几个「门」，不改变任何既有语义。
2. **同一个进程**：不额外拉起引擎进程 —— 否则日志库、学习状态、
   信誉表会被两个进程同时写，数据必然互相覆盖。
3. **额外端口只放行 /v1**：管理接口（/api/*）只留在主端口上，
   避免多开一个门就把配置面、日志面一起暴露出去。
4. **绑不上必须报错**：端口被别的软件占用时静默继续，
   用户会按界面上的地址去改 AI 工具，然后连不上且毫无线索。
"""

from __future__ import annotations

import asyncio
import logging
import os
import socket
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Optional, Set

import uvicorn
from starlette.responses import JSONResponse

logger = logging.getLogger("xuandun-personal.listeners")


class _V1Only:
    """只放行 /v1 路径的 ASGI 包装层。

    ★ 额外端口不对内网开放管理面：
      /api/config 能读到中转站地址与掩码 Key，
      /api/logs 能看到全部对话摘要。这些只该走主端口。
    """

    def __init__(self, app: Any) -> None:
        self._app = app

    async def __call__(self, scope: Dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") == "http":
            path = str(scope.get("path") or "")
            if not path.startswith("/v1"):
                resp = JSONResponse(
                    {
                        "error": {
                            "type": "not_found",
                            "message": (
                                "这个端口只接对话请求（/v1/...）。"
                                "配置与日志在玄盾里查看。"
                            ),
                        }
                    },
                    status_code=404,
                )
                await resp(scope, receive, send)
                return
        await self._app(scope, receive, send)


@dataclass
class _Listener:
    server: uvicorn.Server
    task: "asyncio.Task[None]"
    sock: socket.socket


def _describe_bind_error(port: int, err: OSError) -> str:
    """把 bind 失败翻译成人话。"""
    if getattr(err, "errno", None) in (48, 98, 10048) or "in use" in str(err).lower():
        return (
            f"端口 {port} 已经被别的软件占用了，"
            "请换一个（例如 18803），或先关掉占用它的程序"
        )
    if getattr(err, "errno", None) in (13, 10013):
        return f"系统不允许使用端口 {port}，请换一个 1024 以上的端口"
    return f"端口 {port} 监听失败：{err}"


class RelayPortListeners:
    """额外入口端口的生命周期管理（同一事件循环内增删）。

    ★ 只由 ``proxy.app.run()`` 创建一次；测试里 create_app() 不会创建它，
      所以端口相关接口在没有监听器时会明确告知「需要重启玄盾」，
      而不是假装保存成功。
    """

    def __init__(self, app: Any, host: str, main_port: int) -> None:
        self._app = _V1Only(app)
        self._host = host
        self._main_port = int(main_port)
        self._servers: Dict[int, _Listener] = {}

    # ── 查询 ──

    def ports(self) -> Set[int]:
        return set(self._servers)

    def listening(self, port: int) -> bool:
        return int(port or 0) in self._servers

    # ── 增删 ──

    async def sync(self, desired: Iterable[int]) -> Dict[int, str]:
        """把监听端口对齐到 desired，返回 {失败端口: 原因}。

        ★ 先起后停：新端口起不来时，旧端口保持可用 ——
          用户改了端口却没成功，原来的入口不该跟着消失。
        """
        want = {int(p) for p in desired if p}
        errors: Dict[int, str] = {}

        for port in sorted(want - set(self._servers)):
            err = await self._start(port)
            if err:
                errors[port] = err

        # 失败的新端口不参与「保留」判断：它本来就没起来
        keep = want - set(errors)
        for port in list(set(self._servers) - keep):
            await self._stop(port)
        return errors

    async def close(self) -> None:
        for port in list(self._servers):
            await self._stop(port)

    async def _start(self, port: int) -> Optional[str]:
        if port == self._main_port:
            return f"端口 {port} 是玄盾主入口，请换一个（例如 18801）"

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            # ★ Windows 上**不**设 SO_REUSEADDR。
            #   Windows 的语义是「允许重复绑定」，后绑的进程会静默抢占 ——
            #   端口被别的软件占着时我们会以为绑成功了，
            #   实际请求却发给了别人。这里必须让它老实报错。
            if os.name != "nt":
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self._host, int(port)))
            sock.listen(128)
            sock.setblocking(False)
        except OSError as e:
            try:
                sock.close()
            except OSError:
                pass
            logger.warning("专属端口 %s 监听失败: %s", port, e)
            return _describe_bind_error(port, e)

        server = uvicorn.Server(uvicorn.Config(
            self._app,
            host=self._host,
            port=port,
            # ★ 生命周期只由主服务跑一次，额外端口不能再跑一遍 ——
            #   FastAPI 的 lifespan 会重建存储/日志连接，
            #   跑三遍等于把同一份数据库开三次。
            lifespan="off",
            log_level="warning",
            access_log=False,
            # ★ 不重配日志：多个 uvicorn 服务各自 load 一次日志配置，
            #   会把主服务的日志格式/级别反复覆盖。
            log_config=None,
        ))
        # ★ 不让额外端口接管信号：退出由主服务统一处理，
        #   这里只管跟着进程一起收摊（serve() 本身不装信号处理器）。

        task = asyncio.create_task(server.serve(sockets=[sock]))
        self._servers[port] = _Listener(server=server, task=task, sock=sock)

        for _ in range(100):          # 最多等 2 秒
            if server.started:
                logger.info(
                    "专属入口已开启：http://%s:%s/v1", self._host, port)
                return None
            if task.done():
                break
            await asyncio.sleep(0.02)

        exc = None
        if task.done() and not task.cancelled():
            exc = task.exception()
        logger.warning("专属端口 %s 未能启动: %s", port, exc)
        await self._stop(port)
        return f"端口 {port} 启动失败" + (f"：{exc}" if exc else "，请换一个再试")

    async def _stop(self, port: int) -> None:
        item = self._servers.pop(port, None)
        if item is None:
            return
        item.server.should_exit = True
        try:
            await asyncio.wait_for(item.task, timeout=5)
        except asyncio.TimeoutError:
            item.task.cancel()
        except asyncio.CancelledError:
            pass
        except Exception as e:  # noqa: BLE001 — 收摊失败不该影响其它端口
            logger.info("关闭专属端口 %s 时出错: %s", port, e)
        if not item.task.done():
            item.task.cancel()
        try:
            item.sock.close()
        except OSError:
            pass
        logger.info("专属入口已关闭：%s", port)
