# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白
# 本文件受道体研究许可证 v1.0 约束，禁止逆向工程和再分发
# 详见 LICENSE 文件

"""告警管理器 — 负责分发、去重、频率控制、分级过滤。"""

import time
import logging
from typing import List, Optional, Dict
from .notifiers import AlertEvent, BaseNotifier

logger = logging.getLogger(__name__)

DEFAULT_COOLDOWN = 300  # 5分钟同类告警冷却
SEVERITY_ORDER = {"critical": 3, "important": 2, "info": 1}


class AlertManager:
    """告警管理器：接收告警事件，经去重和分级过滤后分发到已配置的通道。"""

    def __init__(self, notifiers: Optional[List[BaseNotifier]] = None):
        self._notifiers: List[BaseNotifier] = notifiers or []
        self._dedup_cache: Dict[str, float] = {}
        self._cooldown_secs = DEFAULT_COOLDOWN

    def add_notifier(self, notifier: BaseNotifier):
        self._notifiers.append(notifier)
        logger.info("Notifier added: %s", notifier.channel_name)

    def clear_notifiers(self):
        self._notifiers.clear()

    def set_cooldown(self, secs: int):
        self._cooldown_secs = max(0, secs)

    def dispatch(self, event: AlertEvent) -> int:
        """分发告警事件，返回成功发送的通道数。"""
        if self._is_duplicated(event):
            logger.debug("Alert deduplicated: %s/%s", event.event_type, event.attack_category)
            return 0

        sent_count = 0
        for notifier in self._notifiers:
            if not self._should_send(notifier, event):
                continue
            try:
                if notifier.send(event):
                    sent_count += 1
                    logger.info("Alert sent via %s", notifier.channel_name)
                else:
                    logger.warning("Alert send failed via %s", notifier.channel_name)
            except Exception as e:
                logger.error("Notifier %s error: %s", notifier.channel_name, e)

        if sent_count > 0:
            self._mark_sent(event)
        return sent_count

    def _is_duplicated(self, event: AlertEvent) -> bool:
        key = self._dedup_key(event)
        last_sent = self._dedup_cache.get(key, 0)
        return (time.time() - last_sent) < self._cooldown_secs

    def _mark_sent(self, event: AlertEvent):
        key = self._dedup_key(event)
        self._dedup_cache[key] = time.time()

    @staticmethod
    def _dedup_key(event: AlertEvent) -> str:
        return f"{event.event_type}:{event.attack_category or 'unknown'}:{event.reject_stage or 'none'}"

    def _should_send(self, notifier: BaseNotifier, event: AlertEvent) -> bool:
        severity_filter = notifier.config.get("severity_filter", [])
        if severity_filter and event.severity not in severity_filter:
            return False
        if not notifier.validate_config():
            logger.debug("Notifier %s config invalid, skipping", notifier.channel_name)
            return False
        return True
