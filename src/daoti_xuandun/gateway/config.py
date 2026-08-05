# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白
# 本文件受道体研究许可证 v1.0 约束，禁止逆向工程和再分发
# 详见 LICENSE 文件

"""玄盾 AI 安全网关 — 配置加载器与热加载机制。

对应 v2.0 文档 4.1 节 P-05 + Sprint 2b-T03/T06。

热加载机制（评审修订重要-2）：
- watchdog 监听 config/models.yaml 变化（防抖 500ms）
- 写临时文件 → os.rename 原子替换 → 引用切换
- threading.Lock 串行化热加载，防止并发加载
- 校验失败保留旧配置，绝不中断服务
- 请求开始时通过 config = gateway.current_config 获取快照

密钥注入（A-08/P-04）：
- 服务器端通过环境变量 XUANDUN_MODEL_<ID>_KEY 注入
- 启动时校验环境变量是否存在，缺失则模型标记 disabled
- 桌面端只显示"已配置/未配置"状态
"""

from __future__ import annotations

import logging
import os
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple


import yaml
from pydantic import ValidationError

from .schema import GatewayConfig, ModelConfig

logger = logging.getLogger("xuandun-gateway-config")

# watchdog 防抖间隔（毫秒）
_DEBOUNCE_MS = 500


class ConfigLoadError(Exception):
    """配置加载或校验失败。"""


def _check_model_key_env(model: ModelConfig) -> bool:
    """检查模型密钥环境变量是否已配置。

    密钥通过环境变量 XUANDUN_MODEL_<ID>_KEY 注入（A-08）。
    缺失时模型标记 disabled，不阻塞网关启动。
    """
    return bool(os.environ.get(model.backend.api_key_env, ""))


def _apply_key_status(config: GatewayConfig) -> GatewayConfig:
    """根据环境变量检测结果标记模型 enabled 状态。

    由于 schema 是 frozen 的，使用 model_copy 生成新实例。
    缺失密钥的模型 enabled 强制设为 False。
    """
    new_models = []
    changed = False
    for m in config.models:
        key_ok = _check_model_key_env(m)
        if m.enabled and not key_ok:
            logger.warning(
                "模型 %s 密钥环境变量 %s 未配置，标记为 disabled",
                m.id,
                m.backend.api_key_env,
            )
            new_models.append(m.model_copy(update={"enabled": False}))
            changed = True
        else:
            new_models.append(m)

    if changed:
        return config.model_copy(update={"models": tuple(new_models)})
    return config


def load_config_from_dict(data: dict) -> GatewayConfig:
    """从字典构造 GatewayConfig（含密钥环境变量检测）。

    Args:
        data: 已解析的 yaml 字典

    Returns:
        GatewayConfig 不可变实例

    Raises:
        ConfigLoadError: 校验失败
    """
    try:
        raw_config = GatewayConfig.model_validate(data)
    except ValidationError as e:
        raise ConfigLoadError(f"配置校验失败: {e}") from e

    # 应用密钥环境变量检测结果
    return _apply_key_status(raw_config)


def load_config_file(path: str | Path) -> GatewayConfig:
    """从 yaml 文件加载配置。

    Args:
        path: models.yaml 文件路径

    Returns:
        GatewayConfig 不可变实例

    Raises:
        ConfigLoadError: 文件读取或校验失败
    """
    path = Path(path)
    if not path.exists():
        raise ConfigLoadError(f"配置文件不存在: {path}")

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise ConfigLoadError(f"YAML 解析失败: {e}") from e
    except OSError as e:
        raise ConfigLoadError(f"配置文件读取失败: {e}") from e

    if not isinstance(data, dict):
        raise ConfigLoadError(
            f"配置根节点必须是字典，当前类型: {type(data).__name__}"
        )

    return load_config_from_dict(data)


class ConfigManager:
    """配置管理器：加载 + 热加载 + 引用切换。

    线程安全：current_config 属性读取无锁（引用赋值原子），
    热加载通过 _lock 串行化。

    使用方式：
        manager = ConfigManager("config/models.yaml")
        config = manager.current_config  # 请求时获取快照
        manager.start_watching()  # 启动热加载监听
    """

    def __init__(self, config_path: str | Path):
        self._config_path = Path(config_path)
        self._lock = threading.Lock()
        self._current: Optional[GatewayConfig] = None
        self._watcher_thread: threading.Optional[Thread] = None
        self._watcher_stop = threading.Event()
        self._observer = None
        self._last_change_time: float = 0
        self._on_reload_callbacks: List[Callable[[GatewayConfig], None]] = []

    @property
    def current_config(self) -> GatewayConfig:
        """当前配置快照（请求开始时调用）。

        返回不可变配置，热加载时整体替换引用，
        在途请求持有旧引用完成，不受影响。
        """
        if self._current is None:
            raise RuntimeError("配置尚未加载，请先调用 load()")
        return self._current

    def load(self) -> GatewayConfig:
        """首次加载配置。"""
        with self._lock:
            config = load_config_file(self._config_path)
            self._current = config
            logger.info(
                "配置加载成功: %d 模型 (%d enabled), %d 路由",
                len(config.models),
                len(config.get_enabled_models()),
                len(config.routes),
            )
            return config

    def reload(self) -> GatewayConfig:
        """重新加载配置（热加载）。

        校验失败保留旧配置，记录错误，绝不中断服务。
        """
        with self._lock:
            try:
                new_config = load_config_file(self._config_path)
            except ConfigLoadError as e:
                logger.error(
                    "热加载失败，保留旧配置: %s", e, exc_info=True
                )
                # 保留旧配置
                if self._current is None:
                    raise
                return self._current
            except Exception as e:
                logger.error(
                    "热加载异常，保留旧配置: %s", e, exc_info=True
                )
                if self._current is None:
                    raise
                return self._current

            old_config = self._current
            # 原子替换引用
            self._current = new_config
            logger.info(
                "配置热加载成功: %d 模型 (%d enabled), %d 路由",
                len(new_config.models),
                len(new_config.get_enabled_models()),
                len(new_config.routes),
            )

            # 触发回调
            for cb in self._on_reload_callbacks:
                try:
                    cb(new_config)
                except Exception as e:
                    logger.warning("配置热加载回调异常: %s", e)

            return new_config

    def add_reload_callback(
        self, cb: Callable[[GatewayConfig], None]
    ) -> None:
        """注册热加载回调（如 httpx 客户端重建）。"""
        self._on_reload_callbacks.append(cb)

    def start_watching(self) -> None:
        """启动 watchdog 监听配置文件变化。

        使用 watchdog + 防抖 500ms（评审修订重要-2）。
        校验失败保留旧配置。
        """
        try:
            from watchdog.events import FileSystemEventHandler
            from watchdog.observers import Observer
        except ImportError:
            logger.warning(
                "watchdog 未安装，配置热加载不可用。"
                "请安装: pip install watchdog"
            )
            return

        config_path = self._config_path
        watch_dir = str(config_path.parent.resolve())

        class _Handler(FileSystemEventHandler):
            def __init__(self, manager: "ConfigManager"):
                self._manager = manager

            def on_modified(self, event):
                self._maybe_reload(event.src_path)

            def on_created(self, event):
                self._maybe_reload(event.src_path)

            def on_moved(self, event):
                # os.rename 原子替换会触发 moved 事件
                self._maybe_reload(event.dest_path)

            def _maybe_reload(self, src_path: str) -> None:
                # 仅响应目标配置文件
                try:
                    if Path(src_path).resolve() != config_path.resolve():
                        return
                except OSError:
                    return

                # 防抖：500ms 内的多次变更只触发一次重载
                now = time.time()
                self._manager._last_change_time = now

                # 延迟检查防抖
                def _debounced_check():
                    time.sleep(_DEBOUNCE_MS / 1000.0)
                    if (
                        self._manager._last_change_time == now
                        and not self._manager._watcher_stop.is_set()
                    ):
                        logger.info("检测到配置变更，触发热加载")
                        self._manager.reload()

                t = threading.Thread(
                    target=_debounced_check, daemon=True
                )
                t.start()

        if self._observer is not None:
            logger.warning("watchdog 监听已启动，无需重复启动")
            return

        self._observer = Observer()
        self._observer.schedule(
            _Handler(self), path=watch_dir, recursive=False
        )
        self._observer.start()
        logger.info("配置热加载监听已启动: %s", watch_dir)

    def stop_watching(self) -> None:
        """停止 watchdog 监听。"""
        self._watcher_stop.set()
        if self._observer is not None:
            self._observer.stop()
            self._observer.join(timeout=2.0)
            self._observer = None
            logger.info("配置热加载监听已停止")

    def atomic_save(self, data: dict) -> None:
        """原子保存配置到文件（写临时文件 → os.rename 替换）。

        用于管理 API 写入配置时保证原子性，避免半写入状态。
        """
        config_path = self._config_path
        config_path.parent.mkdir(parents=True, exist_ok=True)

        # 写临时文件
        fd, tmp_path = tempfile.mkstemp(
            dir=str(config_path.parent),
            prefix=".models.yaml.",
            suffix=".tmp",
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                yaml.safe_dump(
                    data, f, default_flow_style=False,
                    allow_unicode=True, sort_keys=False
                )
            # 原子替换
            os.replace(tmp_path, config_path)
            logger.info("配置原子保存完成: %s", config_path)
        except Exception:
            # 清理临时文件
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
