# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白
# 本文件受道体研究许可证 v1.0 约束，禁止逆向工程和再分发
# 详见 LICENSE 文件

"""个人版配置。

配置来源优先级：命令行参数 > 环境变量 > SQLite > 默认值
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import paths
from .types import SecurityLevel

logger = logging.getLogger("xuandun-personal.config")

DEFAULT_PORT = 18765

# 地址末段是否已是「版本段」：/v1、/v1beta、/api/v4 …
#
# ★ 判据不能用 `endswith("/v1")`：那只认字面量 /v1，
#   而 /v1beta、/api/v4 会被再拼一层 /v1，请求直接 404。
_VERSION_SEG = re.compile(r"/v\d+[a-z]*$")

# 用户可能连端点一起粘进来的尾巴。
#
# ★ 这不是「用户填错了」，而是产品必须接住的一种输入：
#   中转站后台把「接入地址」与「完整端点」并排展示，用户按
#   配置 API 的直觉复制的是完整端点。实测（2026-09-29）本机
#   配置填的就是 https://api.commandcode.ai/provider/v1/chat/completions。
#   Anthropic 形态（/messages）也一并收下。
_ENDPOINT_TAIL = re.compile(
    r"/(?:chat/completions|completions|messages|responses|embeddings|models)$"
)

# 掩码串的标记（mask_key() 的产物里必然含它）。
_MASK_MARK = "****"


def normalize_relay_base(base_url: str) -> str:
    """把用户粘贴的中转站地址规范化成可用的接入地址。

    ★ v0.1.0 抽成模块级函数。
      原先是 RelayConfig.normalized_base 的实现，
      但多中转站后每一条都要用同一套规范化，
      而它们是 dict 不是 RelayConfig 实例 ——
      继续留在属性里就只能「为了转发临时造一个 RelayConfig」，
      那会让 Key 与地址的对应关系变得难以追踪。
      单一实现同时服务配置页展示与实际转发，两边不会漂移。

    流程：去空白 → 去查询串 → 剥端点 → 补 /v1。
    判据不能用 endswith("/v1")：那只认字面量 /v1，
    而 /v1beta、/api/v4 会被再拼一层 /v1，请求直接 404。
    """
    base = (base_url or "").strip()
    # 从文档复制时常带查询串/锚点，留着会污染请求路径
    for sep in ("?", "#"):
        base = base.split(sep, 1)[0]
    base = base.rstrip("/")
    # 剥掉误粘的端点尾巴（在补 /v1 之前做，才能得到干净的接入地址）
    base = _ENDPOINT_TAIL.sub("", base).rstrip("/")
    if not _VERSION_SEG.search(base):
        base = f"{base}/v1"
    return base


def mask_relay_key(api_key: str) -> str:
    """掩码显示 API Key。

    ★★ P1-5（2026-10-29 第三轮审查）：**空 Key 必须返回空串**。
      原实现对空串也走短 Key 分支返回 ``"***"``，而 ``"***"`` 是真值 ——
      于是设置页的「当前：…」把它当成已配置的 Key 回显出来，
      而真正该走的「尚未配置」分支成了永远到不了的死代码。
      用户看到「当前：***（留空则保持不变）」会以为自己配过 Key，
      之后每一次请求 401 都不会让他想到 Key 其实一直是空的。
      空就是空：界面据此显示「尚未配置」，语义与后端一致。
    """
    if not api_key:
        return ""
    if len(api_key) <= 8:
        return "***"
    return f"{api_key[:4]}{_MASK_MARK}{api_key[-4:]}"


def parse_relay_port(value: Any) -> int:
    """把用户填的端口解析成整数；0 表示「不单独分配」。

    ★ 为什么允许 0 而不是必填：
      绝大多数用户只有一家中转站，主端口本来就够用。
      强制填端口等于让最简单的那条路变复杂。

    ★ 为什么非法值必须抛错而不是静默归零：
      用户填了 18765（正好是主端口）或 70000，静默归零会让界面显示
      「已保存」而端口根本没生效 —— 之后他按界面上的地址改 AI 工具，
      请求全部连不上，却没有任何线索指向这次保存。
    """
    if value is None or value == "":
        return 0
    if isinstance(value, bool):
        raise ValueError("端口必须是数字")
    try:
        port = int(str(value).strip())
    except (TypeError, ValueError) as e:
        raise ValueError("端口必须是数字") from e
    if port == 0:
        return 0
    if not (1024 <= port <= 65535):
        raise ValueError("端口需在 1024–65535 之间")
    return port


def _coerce_port(value: Any) -> int:
    """展示用：非法端口按「未分配」处理（校验由 validate 负责报错）。"""
    try:
        return parse_relay_port(value)
    except ValueError:
        return 0


def is_masked_key(value: Any) -> bool:
    """该值是否是掩码串，而不是真实的 API Key。

    ★ 这是一条**不可省略**的边界校验：
      服务端读取配置时返回的是掩码（``mask_key()`` 的产物），
      前端若原样回传，掩码就会被当成新 Key 写进 config.json ——
      之后所有请求都 401，而配置页上完全看不出异常，
      用户只会以为中转站封了他。失效是静默的，所以判据必须独立存在、
      可被单独测试，而不是埋在某个视图函数里。
    """
    text = str(value or "").strip()
    if not text:
        return False
    # mask_key() 有两种产物：长 Key 的 ``xxxx****yyyy``、短 Key 的 ``***``
    return _MASK_MARK in text or set(text) <= {"*"}


# 配置文件路径
# ★ 统一走 paths.data_dir()：设了 XUANDUN_DATA_DIR 时，
#   开发/测试与稳定版的配置彻底分开，互不污染。
CONFIG_FILE = paths.data_file("config.json")


def _known_fields(cls: type, raw: Any) -> Dict[str, Any]:
    """按 dataclass 声明过滤字段，丢弃配置里的未知键。

    ★ 为什么不直接 `cls(**raw)`：dataclass 对未知关键字抛 TypeError，
      而 load() 把 TypeError 一律当作「配置损坏」整体降级为默认值 ——
      用户的中转站地址、API Key、安全级别、端口会被**全部静默丢弃**。

      典型场景：某版本删掉了某个字段（如 relay.model），
      用户 config.json 里仍留着旧键，升级后所有设置瞬间归零，
      且只留一行 warning。一个过期的键不该有这种杀伤力。
    """
    if not isinstance(raw, dict):
        return {}
    known = {f.name for f in fields(cls)}
    unknown = sorted(set(raw) - known)
    if unknown:
        logger.info("%s 忽略未知配置项: %s", cls.__name__, ", ".join(unknown))
    return {k: v for k, v in raw.items() if k in known}


def _backup_corrupt_config(raw_text: str, err: Exception) -> Optional[Path]:
    """把损坏的配置文件另存一份，返回备份路径（失败返回 None）。

    ★★ 为什么必须有（M2，2026-10-04）
    ────────────────────────────────────────────────────────────
    原实现遇到 JSON 解析失败就 `return PersonalConfig()` ——
    整套设置（中转站地址、API Key、安全级别、端口）静默归零，
    只在日志里留一行 warning。

    更糟的是它**不可逆**：用户此后任何一次保存（改个安全级别、
    暂停防护）都会用「全默认」覆盖掉那个损坏文件 ——
    原始数据从此彻底消失，连人工抢救的机会都没有。

    所以这里在任何降级之前，先把损坏内容落到 sidecar 文件
    （``config.json.corrupt-<时间戳>``），并**用 error 级**打日志。
    配置丢失是用户必须知道的事，不该藏在 info/warning 里。
    """
    try:
        stamp = time.strftime("%Y%m%d-%H%M%S")
        backup = CONFIG_FILE.with_name(f"{CONFIG_FILE.name}.corrupt-{stamp}")
        backup.write_text(raw_text, encoding="utf-8")
        logger.error(
            "配置文件解析失败（%s）。原始内容已备份到 %s；"
            "本次将使用默认配置，请用备份文件人工恢复后覆盖回来，"
            "否则下次保存会用默认值覆盖原文件。",
            err, backup,
        )
        return backup
    except OSError as e:  # noqa: BLE001 — 备份失败不影响降级
        logger.error(
            "配置文件解析失败（%s），且备份失败（%s）："
            "原始设置将丢失，请立即手动检查 %s",
            err, e, CONFIG_FILE,
        )
        return None


@dataclass
class RelayConfig:
    """中转站配置（个人版核心配置）。

    ★ 这里**不**包含 model 字段：玄盾监控的是 API，不是某个模型。
      请求里的 model 原样透传给中转站，玄盾不改写它。

    ★★ v0.1.0：从「单条」扩为「多条 + 一个当前启用项」。
      动机是一个真实的坑：转发时**总是**用这份配置里的 api_key
      （见 app.py::_forward_to_relay），所以
      「AI 工具里填 A 家、玄盾里配 B 家」时，
      用户以为在用 A 扣费，实际扣的是 B —— 账单打错且无人知晓。

      为什么不做「多中转站轮询/负载均衡」：
        ① 带宽不会被摊薄 —— 每个请求本来就只发往一家；
        ② 自动故障转移必须靠**探活**，而探活是真实 HTTP 请求，
           本机实测平均延迟 13123 ms，用它做定期探测等于
           让后台一直在跑慢请求；
        ③ 更根本的：自动切换会让「这次请求扣了谁的钱」变得不可知，
           而这正是多中转站场景下最需要确定的事。
      所以这里只做「按 Key 识别 + 显式切换」，不做自动路由。
    """

    name: str = "默认中转站"           # 显示名
    base_url: str = ""                 # 如 https://api.example.com
    api_key: str = ""                  # 中转站 API Key
    enabled: bool = True

    # ★ v0.1.0：多中转站。新字段全部有默认值，
    #   老配置（只有上面四个字段）加载后自动补齐，不丢任何设置。
    #
    #   存的是**完整副本**而不是引用当前启用项 ——
    #   否则用户改「当前中转站」时会把列表里的原始配置一起改掉，
    #   切回去发现已经不是原来的地址了。
    others: List[Dict[str, Any]] = field(default_factory=list)
    active_id: str = ""                 # 当前启用的 relay id

    # ★ 2026-10-22：每家中转站可以有一个**专属入口端口**。
    #
    #   为什么需要：
    #     多数 AI 工具（IDE 插件等）按「服务地址」区分供应商，
    #     同一地址只允许配一次。用户同时用两家时，
    #     两家的模型 ID 往往一样，工具里根本填不进第二条。
    #     给每家一个独立端口，地址就天然不同了 ——
    #     http://127.0.0.1:18801/v1 与 http://127.0.0.1:18802/v1。
    #
    #   0 = 不单独分配（只有主端口，按 Key 识别，与旧版完全一致）。
    #   端口只决定「从哪个门进来」，不改变转发目标的选择顺序：
    #     从专属端口进来的请求 → 固定发给这家（不看 Key）；
    #     从主端口进来的请求 → 仍按 Key 识别，识别不到用当前启用项。
    port: int = 0

    def validate(self) -> List[str]:
        """校验配置，返回错误列表（空表示通过）。"""
        errors: List[str] = []
        if not self.base_url:
            errors.append("中转站地址不能为空")
        elif not self.base_url.startswith(("http://", "https://")):
            errors.append("中转站地址必须以 http:// 或 https:// 开头")
        if not self.api_key:
            errors.append("中转站 API Key 不能为空")
        # 多中转站：列表里每条都必须自身可用。
        # 不校验的话，用户切到某一家才发现地址打错，
        # 而那时请求已经在往外发了。
        for i, r in enumerate(self.others):
            name = str(r.get("name") or f"#{i + 1}")
            url = str(r.get("base_url") or "")
            if not url:
                errors.append(f"中转站「{name}」地址为空")
            elif not url.startswith(("http://", "https://")):
                errors.append(
                    f"中转站「{name}」地址必须以 http:// 或 https:// 开头"
                )
            if not str(r.get("api_key") or ""):
                errors.append(f"中转站「{name}」API Key 为空")
        errors.extend(self._port_errors())
        return errors

    def _port_errors(self) -> List[str]:
        """专属端口的合法性：范围、重复。

        ★ 重复端口必须在保存前就拦下：
          两个端口撞在一起时，后绑定的那个静默失败，
          界面上两家都显示「已分配端口」，
          而实际只有一家能连 —— 用户会以为另一家坏了。
        """
        errors: List[str] = []
        seen: Dict[int, str] = {}
        for name, raw in self._port_items():
            try:
                port = parse_relay_port(raw)
            except ValueError as e:
                errors.append(f"中转站「{name}」的端口不对：{e}")
                continue
            if port == 0:
                continue
            if port in seen:
                errors.append(
                    f"中转站「{name}」与「{seen[port]}」都用了端口 {port}，"
                    "请给其中一家换一个"
                )
            else:
                seen[port] = name
        return errors

    def _port_items(self):
        """逐条产出 (显示名, 端口原值)，供校验与冲突检测共用一套口径。"""
        yield self.name or "未命名", self.port
        for i, r in enumerate(self.others):
            if not isinstance(r, dict):
                continue
            yield str(r.get("name") or f"#{i + 1}"), r.get("port", 0)

    # ── 多中转站（v0.1.0）──

    @staticmethod
    def make_relay_id(base_url: str, api_key: str) -> str:
        """生成中转站的稳定标识。

        ★ 用「地址 + Key 的哈希」而不是名字或序号：
          名字会重复、序号会随删除而变，
          都会让「切回去」找不到原来的那一家。
          而 Key 一变就是**另一家**了（同一家的 Key 轮换很常见），
          所以把 Key 纳入哈希是符合语义的。
        """
        import hashlib

        raw = f"{base_url}|{api_key}".encode("utf-8")
        return hashlib.sha256(raw).hexdigest()[:12]

    def all_relays(self) -> List[Dict[str, Any]]:
        """返回全部中转站（当前启用的排在最前）。

        ★ 每项都含 id 与 active 标记，前端据此渲染切换列表。
        ★ 2026-10-22：每项都含 port（0 = 未单独分配），
          前端据此展示「这家的入口地址」。
        """
        cur = {
            "id": self.active_id or self.make_relay_id(
                self.base_url, self.api_key),
            "name": self.name,
            "base_url": self.base_url,
            "api_key": self.api_key,
            "enabled": self.enabled,
            "port": _coerce_port(self.port),
            "active": True,
        }
        rest = [
            {**r, "port": _coerce_port(r.get("port", 0)), "active": False}
            for r in self.others if isinstance(r, dict)
        ]
        return [cur] + rest

    def relay_by_port(self, port: int) -> Optional[Dict[str, Any]]:
        """按「请求进来的本地端口」找出该发给哪一家。

        ★ 这是多端口方案的全部判据：从专属端口进来的请求，
          固定发往拥有该端口的那家，**不看 Key**。
          理由：AI 工具里填的 Key 常常是占位串（很多 IDE 只允许
          任意非空值），真正决定扣谁的钱应该是用户在这个端口上
          明确选定的那一家。
        """
        if not port:
            return None
        for r in self.all_relays():
            if not r.get("enabled", True):
                continue
            if int(r.get("port") or 0) == int(port):
                return r
        return None

    def assigned_ports(self) -> Dict[int, str]:
        """返回 {端口: 中转站显示名}，供监听与界面展示共用。

        0 不在此列（未单独分配）；已停用的那家也不监听 ——
        停用意味着「别用它」，再占一个端口只会让用户困惑。
        """
        out: Dict[int, str] = {}
        for r in self.all_relays():
            if not r.get("enabled", True):
                continue
            port = int(r.get("port") or 0)
            if port:
                out[port] = str(r.get("name") or "未命名")
        return out

    def relay_by_key(self, api_key: str) -> Optional[Dict[str, Any]]:
        """按 API Key 找出对应中转站；找不到返回 None。

        ★ 这是「账单打不错」的关键。
          转发时若拿到的 Key 能匹配上某一家，就用那家的地址，
          否则用当前启用项 —— 后者是兼容老配置的回退。

          刻意**不做**「匹配不到就报错」：
          用户可能刚在别处换了 Key，还没同步到玄盾，
          此时直接拒绝会让整个 AI 工具不可用，
          而静默用当前启用项只是延续现状（不会更糟）。
        """
        if not api_key:
            return None
        for r in self.all_relays():
            if r.get("api_key") and r["api_key"] == api_key:
                return r
        return None

    @property
    def normalized_base(self) -> str:
        """规范化地址：去空白 → 去查询串 → 剥端点 → 补 /v1。

        ★ 设计前提：**用户不该需要知道地址该填到哪一段**。
          中转站给什么形式就粘什么 —— 带 /v1、不带 /v1、
          连完整端点一起、带查询串、Anthropic 形态，
          都要能直接用。要求用户先理解 base_url 与 endpoint 的区别，
          等于把配置门槛推给了最不懂的人。

        ★ 实测（2026-09-29）本机配置填的是
          ``https://api.commandcode.ai/provider/v1/chat/completions``。
          旧判据 ``endswith("/v1")`` 不成立 → 拼成
          ``.../chat/completions/v1/chat/completions``，该地址实测返回
          404「is not a registered route」；本属性拼出的
          ``.../provider/v1/chat/completions`` 实测路由命中
          （返回的是模型不支持，属另一层问题）。
        """
        return normalize_relay_base(self.base_url)

    def mask_key(self) -> str:
        """掩码显示 API Key。"""
        return mask_relay_key(self.api_key)


@dataclass
class GuardConfig:
    """防护配置。"""

    security_level: str = SecurityLevel.BALANCED.value
    enable_response_verify: bool = True    # 响应验证
    enable_request_sanitize: bool = True   # 请求脱敏
    enable_reputation: bool = True          # 中转站评估
    enable_pattern_check: bool = True      # 响应模式异常检测
    # 敏感类型开关
    # ★ P1-5 修复：文档 4.4 图示中「银行卡」「自定义关键词」默认未勾选，
    #   原实现全部默认 True；由于 bankcard 三级均为 BLOCK，默认勾选时
    #   误命中 16-19 位数字会直接阻断整个请求，比文档预期严格得多。
    enabled_categories: Dict[str, bool] = field(default_factory=lambda: {
        "api_key": True,
        "aws_key": True,
        "private_key": True,
        "jwt": True,
        "idcard": True,
        "phone": True,
        "email": True,
        "bankcard": False,   # 文档默认未勾选（误报率高，命中即阻断）
        "custom": False,     # 文档默认未勾选
    })
    custom_keywords: List[str] = field(default_factory=list)

    def validate(self) -> List[str]:
        errors: List[str] = []
        if self.security_level not in (s.value for s in SecurityLevel):
            errors.append(f"无效的安全级别: {self.security_level}")
        return errors


@dataclass
class ServerConfig:
    """代理服务配置。"""

    host: str = "127.0.0.1"        # 只监听本地（安全底线）
    port: int = DEFAULT_PORT
    log_level: str = "INFO"
    request_timeout_s: int = 300     # 上游超时（与流式长响应兼容）

    def validate(self) -> List[str]:
        errors: List[str] = []
        if not (1024 <= self.port <= 65535):
            errors.append(f"端口超出合法范围: {self.port}")
        if self.host not in ("127.0.0.1", "localhost", "::1"):
            errors.append(
                f"个人版代理只允许监听本地（当前 {self.host}），"
                "如需远程访问请使用企业版网关"
            )
        return errors


@dataclass
class StorageConfig:
    """本地存储配置。

    ★ 2026-10-20：此前日志只增不减，一天一千条约 0.5–1 MB，
      一年就是几百 MB，而界面没有任何清理入口或提示。
      默认 0 = 永久保留（不替用户做删除决定），
      用户可显式选择保留天数，超期记录在保存时与启动时清理。
    """

    log_retention_days: int = 0     # 0 = 永久保留

    def validate(self) -> List[str]:
        if not (0 <= int(self.log_retention_days) <= 3650):
            return ["日志保留天数必须在 0（永久）到 3650 之间"]
        return []


@dataclass
class PersonalConfig:
    """个人版完整配置。"""

    relay: RelayConfig = field(default_factory=RelayConfig)
    guard: GuardConfig = field(default_factory=GuardConfig)
    server: ServerConfig = field(default_factory=ServerConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)

    def validate(self, only: Optional[List[str]] = None) -> List[str]:
        """校验配置，返回错误列表（空表示通过）。

        Args:
            only: 只校验这些分片（``relay`` / ``guard`` / ``server`` /
                  ``storage``）；``None`` = 全量。

        ★★ 2026-10-29（第三轮审查 P0-3）：加 ``only`` 的直接原因是
          一次真实的「守卫堵死正常路径」——
          首启向导允许「先跳过，进主界面看看」（Onboarding.tsx），
          此时 relay 是空的；而 update_config 无条件做**全量**校验，
          于是用户改安全级别、改端口、改日志保留天数**全部 400**，
          报的还是与他操作无关的「中转站地址不能为空」。

          校验的语义应当是「这次要写的东西是否合法」，
          不是「整份配置是否完美」。其它调用方（启动、加中转站、
          切换）保持全量，行为不变。
        """
        scopes = (
            {"relay", "guard", "server", "storage"}
            if only is None
            else set(only)
        )
        errors: List[str] = []
        if "server" in scopes:
            errors.extend(self.server.validate())
        if "guard" in scopes:
            errors.extend(self.guard.validate())
        if "storage" in scopes:
            errors.extend(self.storage.validate())
        if "relay" in scopes and self.relay.enabled:
            errors.extend(self.relay.validate())
            # ★ 专属端口不能与主端口相同：主端口已有唯一语义
            #   （按 Key 识别 / 未识别用当前启用项），
            #   再把它分配给某一家会让「从主端口进来的请求到底发给谁」
            #   变成两套规则打架。
            for name, raw in self.relay._port_items():
                if _coerce_port(raw) == self.server.port:
                    errors.append(
                        f"中转站「{name}」的端口 {self.server.port} "
                        "与玄盾主端口相同，请换一个（例如 18801）"
                    )
        return errors

    def is_valid(self) -> bool:
        return len(self.validate()) == 0

    # ── 持久化 ──

    @staticmethod
    def load() -> "PersonalConfig":
        """从配置文件加载（不存在则返回默认配置）。"""
        if not CONFIG_FILE.exists():
            logger.info("配置文件不存在，使用默认配置: %s", CONFIG_FILE)
            return PersonalConfig()

        # ★ M2 修复：把「读不出来」与「解析不了」分开处理。
        #   只有后者才是「文件损坏」，需要备份；前者读不到内容，
        #   备份也无从谈起（备份空字符串没意义）。
        try:
            raw_text = CONFIG_FILE.read_text(encoding="utf-8-sig")
        except OSError as e:
            logger.warning("配置文件读取失败（%s），使用默认配置", e)
            return PersonalConfig()

        try:
            # ★★ 必须用 utf-8-sig 而不是 utf-8。
            #   Windows 记事本、PowerShell 的 Out-File、某些同步工具
            #   写出的文本文件会带 UTF-8 BOM。utf-8 会把它当成
            #   JSON 的第一个字符而抛「Unexpected UTF-8 BOM」——
            #   用户的全部设置（中转站地址、安全级别、API Key）
            #   随之被丢弃，且只留一行 warning，多数人不会注意到。
            #   utf-8-sig 对有无 BOM 都正确，是这里唯一该用的编码。
            raw = json.loads(raw_text)
        except json.JSONDecodeError as e:
            # ★ M2：先备份再降级，避免后续 save() 把这唯一的原始数据覆盖掉
            _backup_corrupt_config(raw_text, e)
            return PersonalConfig()

        # ★★ P1-1（2026-10-29 第三轮审查）：**JSON 合法但顶层不是对象**。
        #   `[]` / `null` / `"x"` 都能通过 json.loads，却在下面
        #   `raw.get("relay", {})` 处抛 AttributeError ——
        #   它不落进上面的 JSONDecodeError 分支，也不落进下面的
        #   TypeError 分支（外层没有 except AttributeError），
        #   于是引擎启动时直接崩掉：界面永远起不来、配置页也打不开，
        #   而磁盘上的文件其实完全可读。
        #
        #   处理方式与「JSON 解析失败」一致：**先备份再降级为默认配置**。
        #   不能只 `return PersonalConfig()` —— 那会让用户此后任何一次
        #   保存都把这份还看得懂的原始内容覆盖掉，连人工抢救的机会都没了。
        if not isinstance(raw, dict):
            _backup_corrupt_config(
                raw_text,
                ValueError(
                    f"配置文件顶层必须是 JSON 对象，实际是 {type(raw).__name__}"
                ),
            )
            return PersonalConfig()

        try:
            return PersonalConfig(
                relay=RelayConfig(**_known_fields(RelayConfig, raw.get("relay", {}))),
                guard=GuardConfig(**_known_fields(GuardConfig, raw.get("guard", {}))),
                server=ServerConfig(**_known_fields(ServerConfig, raw.get("server", {}))),
                storage=StorageConfig(
                    **_known_fields(StorageConfig, raw.get("storage", {}))
                ),
            )
        except TypeError as e:
            logger.warning("配置字段不匹配（%s），使用默认配置", e)
            return PersonalConfig()

    def save(self) -> Path:
        """保存到配置文件。"""
        CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "relay": asdict(self.relay),
            "guard": asdict(self.guard),
            "server": asdict(self.server),
            "storage": asdict(self.storage),
        }
        # ★ 磁盘上必须留**明文** Key（含 others 里的每一条）——
        #   否则重启后无法按 Key 识别中转站，转发会 401。
        #   这与单条 relay.api_key 的处理一致。
        #   对外一律走 to_safe_dict（逐条掩码），文件权限在下方设为 0o600。
        CONFIG_FILE.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        # Windows 下配置文件不应对其他用户可读（含 API Key）
        try:
            os.chmod(CONFIG_FILE, 0o600)
        except OSError:
            pass
        logger.info("配置已保存: %s", CONFIG_FILE)
        return CONFIG_FILE

    # ── 环境变量覆盖 ──

    def apply_env_overrides(self) -> None:
        """应用环境变量覆盖（便于 CI / 脚本化配置）。

        ★★ P1-9（2026-10-28）：端口变量名必须与桌面端（Rust）一致。
        ────────────────────────────────────────────────────────────
        Rust 读的是 ``XUANDUN_PROXY_PORT``，这里原读 ``XUANDUN_PERSONAL_PORT``：
        照文档做端口隔离时，桌面端连 A、引擎听 B —— 双方各自"正常"，
        只有用户看到「引擎启动失败」。

        现在两侧都认**两个**名字，规范名优先，旧名保留兼容（会打一条提示）。
        """
        if v := os.getenv("XUANDUN_PERSONAL_RELAY_URL"):
            self.relay.base_url = v
        if v := os.getenv("XUANDUN_PERSONAL_RELAY_KEY"):
            self.relay.api_key = v
        port_raw = os.getenv("XUANDUN_PROXY_PORT")
        if not port_raw and (legacy := os.getenv("XUANDUN_PERSONAL_PORT")):
            port_raw = legacy
            logger.warning(
                "XUANDUN_PERSONAL_PORT 是历史名称，请改用 XUANDUN_PROXY_PORT"
                "（桌面端只认规范名时会出现「端口隔离无效」）"
            )
        if port_raw:
            try:
                self.server.port = int(port_raw)
            except ValueError:
                logger.warning("无效的端口环境变量: %s", port_raw)
        if v := os.getenv("XUANDUN_PERSONAL_LEVEL"):
            self.guard.security_level = v
        logger.info("已应用环境变量覆盖")

    # ── 脱敏视图（供 API 返回，不含密钥明文）──

    def to_safe_dict(self) -> Dict[str, Any]:
        """返回不含 API Key 明文的配置视图。

        ★ 多中转站的每一项都要单独掩码。
          漏掉任何一条都等于把该家的 Key 明文发给前端 ——
          前端是 Tauri 窗口内的 WebView，但它仍可能被
          截图、注入脚本或日志采集拿到。
        """
        relay = asdict(self.relay)
        relay["api_key"] = self.relay.mask_key()
        # others 是 list[dict]，asdict 已深拷贝过，
        # 这里可以安全就地替换而不会改到 self.relay.others。
        relay["others"] = [
            {**r, "api_key": mask_relay_key(str(r.get("api_key") or ""))}
            for r in self.relay.others
        ]
        return {
            "relay": relay,
            "guard": asdict(self.guard),
            "server": asdict(self.server),
            "storage": asdict(self.storage),
        }
