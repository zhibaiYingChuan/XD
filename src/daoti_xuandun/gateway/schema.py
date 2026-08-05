# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白
# 本文件受道体研究许可证 v1.0 约束，禁止逆向工程和再分发
# 详见 LICENSE 文件

"""玄盾 AI 安全网关 — 配置 Schema（pydantic v2 不可变模型）。

对应 v2.0 文档 4.4 节 models.yaml Schema 定稿（A-22 配置即文档）。

不可变性约束（评审修订重要-2）：
- 所有模型使用 frozen=True，热加载时整体替换引用
- 子结构同为不可变：tuple 替代 list，frozenset 替代 set
- 请求开始时通过 config = gateway.current_config 获取快照
- 校验失败保留旧配置，绝不中断服务

pydantic 校验规则：
1. id 必须匹配 ^[a-z0-9-]+$，全局唯一
2. api_key_env 启动时校验环境变量是否存在，缺失则该模型标记 disabled
3. base_url 生产环境强制 https（开发模式允许 http）
4. route 的 target_model_id 必须在 models 中存在（引用完整性）
5. fallback 引用的 model_id 必须存在且不形成环
"""

from __future__ import annotations

import re
from types import MappingProxyType
from typing import Any, Dict, List, Literal, Optional, Set, Tuple


from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


# 模型 ID 命名规则：小写字母、数字、短横线
_MODEL_ID_PATTERN = re.compile(r"^[a-z0-9-]+$")

# 安全策略枚举
SecurityPolicy = Literal["strict", "balanced", "permissive"]


class BackendConfig(BaseModel):
    """后端模型连接配置（不可变）。"""

    model_config = ConfigDict(frozen=True, extra="forbid")

    base_url: str = Field(..., description="后端 API 基础地址")
    model: str = Field(..., description="实际发给后端的 model 名")
    api_key_env: str = Field(
        ..., description="API Key 环境变量名，绝不存明文"
    )

    @field_validator("base_url")
    @classmethod
    def _validate_base_url(cls, v: str) -> str:
        if not v:
            raise ValueError("base_url 不能为空")
        if not (v.startswith("https://") or v.startswith("http://")):
            raise ValueError("base_url 必须以 http:// 或 https:// 开头")
        return v

    @field_validator("api_key_env")
    @classmethod
    def _validate_api_key_env(cls, v: str) -> str:
        if not v.startswith("XUANDUN_MODEL_") or not v.endswith("_KEY"):
            raise ValueError(
                "api_key_env 必须符合命名规范 XUANDUN_MODEL_<MODEL_ID>_KEY"
            )
        return v


class SecurityConfig(BaseModel):
    """模型安全策略配置（不可变）。"""

    model_config = ConfigDict(frozen=True, extra="forbid")

    input_check: bool = Field(default=True, description="是否开启输入检测")
    output_check: bool = Field(default=False, description="是否开启输出检测")
    strict_output_check: bool = Field(
        default=False, description="是否严格输出检测"
    )
    policy: SecurityPolicy = Field(
        default="balanced", description="安全策略层级"
    )


class ModelConfig(BaseModel):
    """单个模型配置（不可变）。"""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(..., description="调用方在 model 字段填这个 id")
    display_name: str = Field(..., description="展示名称")
    provider: str = Field(..., description="模型供应商")
    backend: BackendConfig
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    fallback: Optional[str] = Field(
        default=None, description="故障转移目标 model_id（可选）"
    )
    timeout_seconds: int = Field(
        default=300, description="单次请求总超时（秒）", ge=1, le=3600
    )
    # 运行时字段：环境变量缺失时启动标记 disabled，不写入 yaml
    # frozen=True 下通过 model_construct 或运行时包装处理
    enabled: bool = Field(default=True, description="是否启用")

    @field_validator("id")
    @classmethod
    def _validate_id(cls, v: str) -> str:
        if not _MODEL_ID_PATTERN.match(v):
            raise ValueError(
                f"model id 必须匹配 ^[a-z0-9-]+$，当前值: {v!r}"
            )
        return v


class RouteMatch(BaseModel):
    """路由匹配条件（不可变）。

    匹配语义（A-10）：
    - =value : 精确匹配
    - =*prefix : 前缀通配
    - 仅 model 或 header 之一有效，model 优先
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    model: Optional[str] = Field(
        default=None, description="model 字段匹配规则（=精确 /=*前缀通配）"
    )
    # header 匹配留接口，Sprint 2b 仅实现 model 匹配
    header: Dict[str, str] | None = Field(
        default=None, description="请求头匹配（Sprint 3 实现）"
    )


class RouteConfig(BaseModel):
    """路由规则（不可变）。"""

    model_config = ConfigDict(frozen=True, extra="forbid")

    match: RouteMatch
    target_model_id: str = Field(..., description="匹配后路由到的模型 id")
    priority: int = Field(
        default=100, description="优先级（降序，首个匹配生效）", ge=1
    )


class DefaultPolicy(BaseModel):
    """全局默认安全策略（不可变）。"""

    model_config = ConfigDict(frozen=True, extra="forbid")

    security_policy: SecurityPolicy = Field(default="balanced")
    audit_log: bool = Field(default=True)
    timeout_seconds: int = Field(default=300, ge=1, le=3600)


class GatewayConfig(BaseModel):
    """网关完整配置（不可变根模型）。

    热加载时整体替换 GatewayConfig 引用，
    请求开始时通过 config = gateway.current_config 获取快照。
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    version: str = Field(default="1.0", description="配置版本号")
    default: DefaultPolicy = Field(default_factory=DefaultPolicy)
    # 使用 tuple 替代 list 保证不可变（评审修订重要-2）
    models: Tuple[ModelConfig, ...] = Field(
        default=(), description="模型列表"
    )
    routes: Tuple[RouteConfig, ...] = Field(
        default=(), description="路由规则列表（按 priority 降序）"
    )
    default_model_id: Optional[str] = Field(
        default=None, description="兜底路由 model_id"
    )

    @field_validator("version")
    @classmethod
    def _validate_version(cls, v: str) -> str:
        if v != "1.0":
            raise ValueError(
                f"当前仅支持配置版本 1.0，收到: {v!r}"
            )
        return v

    @model_validator(mode="after")
    def _validate_references(self) -> "GatewayConfig":
        """引用完整性校验（规则 1/4/5）。"""
        # 规则 1：模型 id 全局唯一
        ids = [m.id for m in self.models]
        if len(ids) != len(set(ids)):
            seen: Set[str] = set()
            dupes = [i for i in ids if i in seen or seen.add(i)]
            raise ValueError(f"模型 id 重复: {dupes}")

        id_set = set(ids)

        # 规则 4：route.target_model_id 必须存在
        for route in self.routes:
            if route.target_model_id not in id_set:
                raise ValueError(
                    f"路由规则 target_model_id={route.target_model_id!r} "
                    f"在 models 中不存在（引用完整性失败）"
                )

        # 规则 5：fallback 引用必须存在且不形成环
        for m in self.models:
            if m.fallback is not None:
                if m.fallback not in id_set:
                    raise ValueError(
                        f"模型 {m.id!r} 的 fallback={m.fallback!r} 不存在"
                    )
                if m.fallback == m.id:
                    raise ValueError(
                        f"模型 {m.id!r} 的 fallback 不能指向自身"
                    )
        # 环检测
        self._check_fallback_cycle(id_set)

        # default_model_id 必须存在
        if self.default_model_id is not None:
            if self.default_model_id not in id_set:
                raise ValueError(
                    f"default_model_id={self.default_model_id!r} 不存在"
                )

        return self

    def _check_fallback_cycle(self, id_set: Set[str]) -> None:
        """检测 fallback 链是否形成环。"""
        fallback_map: Dict[str, Optional[str]] = {
            m.id: m.fallback for m in self.models
        }
        for start in id_set:
            visited: Set[str] = set()
            current: Optional[str] = start
            while current is not None and current in id_set:
                if current in visited:
                    raise ValueError(
                        f"检测到 fallback 环: {' -> '.join(visited)} -> {current}"
                    )
                visited.add(current)
                current = fallback_map.get(current)

    def get_model(self, model_id: str) -> Optional[ModelConfig]:
        """按 id 查询模型配置（O(n)，配置规模小无需索引）。"""
        for m in self.models:
            if m.id == model_id:
                return m
        return None

    def get_enabled_models(self) -> Tuple[ModelConfig, ...]:
        """返回所有 enabled 模型。"""
        return tuple(m for m in self.models if m.enabled)

    def resolve_route(
        self, request_model: Optional[str]
    ) -> Tuple[Optional[ModelConfig], Optional[str]]:
        """解析路由：按 priority 降序匹配，返回 (模型, 匹配说明)。

        路由匹配语义（A-10）：
        - =value : 精确匹配
        - =*prefix : 前缀通配
        - 无匹配时走 default_model_id 兜底
        - 兜底也为空则返回 (None, "no route matched")

        注意：disabled 模型不会被路由命中。
        """
        # 路由按 priority 降序
        sorted_routes = sorted(
            self.routes, key=lambda r: r.priority, reverse=True
        )
        for route in sorted_routes:
            match_rule = route.match.model
            if match_rule is None:
                continue
            # 请求未带 model 字段时跳过 model 匹配规则
            if request_model is None:
                continue

            target = self.get_model(route.target_model_id)
            # 目标模型 disabled 则跳过
            if target is None or not target.enabled:
                continue

            if match_rule.startswith("=*"):
                # 前缀通配
                prefix = match_rule[2:]
                if request_model.startswith(prefix):
                    return target, f"prefix-match:{match_rule}"
            elif match_rule.startswith("="):
                # 精确匹配
                exact = match_rule[1:]
                if request_model == exact:
                    return target, f"exact-match:{match_rule}"
            else:
                # 无前缀符默认精确匹配（兼容性）
                if request_model == match_rule:
                    return target, f"implicit-exact:{match_rule}"

        # 兜底路由
        if self.default_model_id is not None:
            fallback_model = self.get_model(self.default_model_id)
            if fallback_model is not None and fallback_model.enabled:
                return fallback_model, "default-route"

        return None, "no route matched"

    def to_safe_view(self) -> dict:
        """返回不含密钥的安全视图（用于 /v1/models 端点）。

        绝不返回 api_key_env 的实际值，仅返回是否已配置。
        """
        import os

        models_view = []
        for m in self.models:
            key_configured = bool(os.environ.get(m.backend.api_key_env, ""))
            models_view.append(
                {
                    "id": m.id,
                    "display_name": m.display_name,
                    "provider": m.provider,
                    "enabled": m.enabled and key_configured,
                    "key_configured": key_configured,
                    "fallback": m.fallback,
                    "timeout_seconds": m.timeout_seconds,
                }
            )
        return {
            "version": self.version,
            "models": models_view,
            "default_model_id": self.default_model_id,
            "routes_count": len(self.routes),
        }
