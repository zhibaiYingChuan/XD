"""
多模型路由引擎 — 根据请求头/请求体字段分发到不同模型后端

路由规则优先级:
  1. X-Model-ID 请求头（显式指定）
  2. 请求体中 model 字段（自动路由）
  3. 配置中 default_model 回退
"""
import yaml
import os
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from pathlib import Path


@dataclass
class ModelRoute:
    """单个模型路由配置"""
    id: str
    name: str = ""
    endpoint: str = ""
    type: str = "public"   # public / private
    api_key: str = ""
    routes: List[Dict] = field(default_factory=list)
    weight: float = 100.0

    def mask_api_key(self) -> str:
        """遮盖 API Key 用于日志输出"""
        if len(self.api_key) <= 8:
            return "***"
        return self.api_key[:4] + "****" + self.api_key[-4:]


@dataclass
class RouterConfig:
    """路由配置"""
    models: Dict[str, ModelRoute] = field(default_factory=dict)
    strategy: str = "weighted"          # weighted / round_robin / first_match
    default_model: str = ""             # 默认回退模型
    hot_reload_enabled: bool = True     # 是否启用热加载
    last_loaded: float = 0.0            # 最后加载时间戳

    def get_model_ids(self) -> List[str]:
        return list(self.models.keys())

    def get_model_count(self) -> int:
        return len(self.models)


class ModelRouter:
    """多模型路由引擎 — 单例模式，支持热加载"""

    def __init__(self, config_path: Optional[str] = None):
        self._config_path = config_path
        self._config = RouterConfig()
        self._file_mtime: float = 0.0
        self.load_config()

    def load_config(self) -> RouterConfig:
        """加载/重新加载路由配置"""
        if not self._config_path or not os.path.exists(self._config_path):
            self._config = RouterConfig()
            return self._config

        try:
            file_mtime = os.path.getmtime(self._config_path)
            if file_mtime == self._file_mtime:
                return self._config  # 无变化，跳过

            with open(self._config_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}

            models = {}
            for m in data.get("models", []):
                model_id = m.get("id", "")
                if not model_id:
                    continue
                models[model_id] = ModelRoute(
                    id=model_id,
                    name=m.get("name", model_id),
                    endpoint=m.get("endpoint", ""),
                    type=m.get("type", "public"),
                    api_key=m.get("api_key", ""),
                    routes=m.get("routes", []),
                    weight=m.get("weight", 100.0),
                )

            routing = data.get("routing", {})
            self._config = RouterConfig(
                models=models,
                strategy=routing.get("strategy", "weighted"),
                default_model=routing.get("default", ""),
                hot_reload_enabled=data.get("config", {}).get("hot_reload", True),
                last_loaded=time.time(),
            )
            self._file_mtime = file_mtime

        except Exception as e:
            # 加载失败时保留旧配置
            pass

        return self._config

    def reload(self) -> Dict:
        """热加载配置 — POST /api/config/reload 调用"""
        old_count = self._config.get_model_count()
        self.load_config()
        new_count = self._config.get_model_count()
        return {
            "success": True,
            "previous_models": old_count,
            "current_models": new_count,
            "model_ids": self._config.get_model_ids(),
        }

    def resolve(self, x_model_id: Optional[str] = None,
                request_body: Optional[Dict] = None) -> Optional[ModelRoute]:
        """
        解析目标模型路由

        优先级: X-Model-ID > request_body.model > default_model
        """
        # 1. 显式指定 X-Model-ID 请求头
        if x_model_id and x_model_id in self._config.models:
            return self._config.models[x_model_id]

        # 2. 请求体中的 model 字段
        if request_body and "model" in request_body:
            model_field = request_body["model"]
            if model_field in self._config.models:
                return self._config.models[model_field]

        # 3. 默认回退模型
        if self._config.default_model and self._config.default_model in self._config.models:
            return self._config.models[self._config.default_model]

        # 4. 无模型可路由
        return None

    def get_stats(self) -> Dict:
        """获取路由统计"""
        return {
            "models": self._config.get_model_ids(),
            "model_count": self._config.get_model_count(),
            "strategy": self._config.strategy,
            "default_model": self._config.default_model,
            "hot_reload": self._config.hot_reload_enabled,
            "last_reload": self._config.last_loaded,
        }
