"""
玄盾网关配置加载器 — 支持 YAML 文件 + 环境变量双路径

优先级: 环境变量 > YAML 文件 > 默认值
"""
import os
import yaml
from dataclasses import dataclass, field
from typing import Dict, List, Optional


DEFAULT_CONFIG_YAML = """
# 玄盾网关默认配置
gateway:
  host: "0.0.0.0"
  port: 18765
  log_level: "info"

security:
  mode: "protecting"           # observing / protecting / blocking
  defense_level: "standard"    # standard / strict / permissive
  output_guardrail: true
  sensitive_leak: true
  gray_deploy_ratio: 1.0       # 灰度部署：0.0~1.0，表示实际拦截的请求比例（1.0=全量拦截）

models: []                     # 多模型路由配置

notifiers: {}                  # 告警通道配置（dingtalk/feishu/email/webhook/syslog）
"""


@dataclass
class GatewayConfig:
    """网关服务配置"""
    host: str = "0.0.0.0"
    port: int = 18765
    log_level: str = "info"


@dataclass
class SecurityConfig:
    """安全策略配置"""
    mode: str = "protecting"
    defense_level: str = "standard"
    output_guardrail: bool = True
    sensitive_leak: bool = True
    # 阈值默认值
    structural_threshold: float = 0.60
    binary_threshold: float = 0.50
    temporal_threshold: float = 0.55


@dataclass
class ModelConfig:
    """模型路由配置"""
    id: str = ""
    name: str = ""
    endpoint: str = ""
    type: str = "public"       # public / private
    api_key: str = ""
    routes: List[Dict] = field(default_factory=list)


@dataclass
class XuanDunGatewayConfig:
    """玄盾网关完整配置"""
    gateway: GatewayConfig = field(default_factory=GatewayConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    models: List[ModelConfig] = field(default_factory=list)


def _env(key: str, default: str = "") -> str:
    """读取环境变量，支持 XUANDUN_ 前缀"""
    val = os.getenv(f"XUANDUN_{key}", "")
    if val:
        return val
    return os.getenv(key, default)


def load_config(config_path: Optional[str] = None) -> XuanDunGatewayConfig:
    """
    加载配置: YAML 文件 + 环境变量覆盖

    环境变量映射:
      XUANDUN_MODE          → security.mode
      XUANDUN_LOG_LEVEL     → gateway.log_level
      XUANDUN_PORT          → gateway.port
      XUANDUN_DEFENSE_LEVEL → security.defense_level
    """
    # 1. 加载 YAML 文件
    yaml_data = {}
    if config_path and os.path.exists(config_path):
        with open(config_path, "r", encoding="utf-8") as f:
            yaml_data = yaml.safe_load(f) or {}

    # 2. 环境变量覆盖
    gateway_cfg = GatewayConfig(
        host=yaml_data.get("gateway", {}).get("host", "0.0.0.0"),
        port=int(_env("PORT", str(yaml_data.get("gateway", {}).get("port", 18765)))),
        log_level=_env("LOG_LEVEL", yaml_data.get("gateway", {}).get("log_level", "info")),
    )

    security_cfg = SecurityConfig(
        mode=_env("MODE", yaml_data.get("security", {}).get("mode", "protecting")),
        defense_level=_env("DEFENSE_LEVEL",
                           yaml_data.get("security", {}).get("defense_level", "standard")),
        output_guardrail=yaml_data.get("security", {}).get("output_guardrail", True),
        sensitive_leak=yaml_data.get("security", {}).get("sensitive_leak", True),
    )

    # 3. 模型路由配置（仅从 YAML 读取）
    models = []
    for m in yaml_data.get("models", []):
        models.append(ModelConfig(
            id=m.get("id", ""),
            name=m.get("name", ""),
            endpoint=m.get("endpoint", ""),
            type=m.get("type", "public"),
            api_key=m.get("api_key", ""),
            routes=m.get("routes", []),
        ))

    return XuanDunGatewayConfig(
        gateway=gateway_cfg,
        security=security_cfg,
        models=models,
    )
