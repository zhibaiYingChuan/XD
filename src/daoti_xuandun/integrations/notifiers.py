# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白
# 本文件受道体研究许可证 v1.0 约束，禁止逆向工程和再分发
# 详见 LICENSE 文件

"""告警通道抽象层 — 支持钉钉/飞书/邮件/Webhook/Syslog 五大通道。

每个通道继承 BaseNotifier，实现 send() 和 validate_config()。
AlertEvent 为统一的告警事件数据结构，由 AlertManager 分发。
"""

import hashlib
import hmac
import base64
import time
import json
import socket
import logging
import smtplib
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List
from abc import ABC, abstractmethod
from urllib import request as url_request
from urllib.error import URLError

logger = logging.getLogger(__name__)

SEVERITY_LABELS = {
    "critical": "紧急",
    "important": "重要",
    "info": "普通",
}


@dataclass
class AlertEvent:
    event_type: str
    severity: str
    timestamp: str
    attack_category: Optional[str] = None
    trust_level: str = ""
    reject_stage: Optional[str] = None
    text_preview: str = ""
    engine_mode: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_type": self.event_type,
            "severity": self.severity,
            "timestamp": self.timestamp,
            "attack_category": self.attack_category,
            "trust_level": self.trust_level,
            "reject_stage": self.reject_stage,
            "text_preview": self.text_preview,
            "engine_mode": self.engine_mode,
            "extra": self.extra,
        }


class BaseNotifier(ABC):
    channel_name = "base"

    def __init__(self, config: dict):
        self.config = config

    @abstractmethod
    def send(self, event: AlertEvent) -> bool:
        ...

    @abstractmethod
    def validate_config(self) -> bool:
        ...

    def _format_message(self, event: AlertEvent) -> str:
        sev = SEVERITY_LABELS.get(event.severity, event.severity)
        cat = event.attack_category or "未知"
        lines = [
            f"【道体·玄盾 {sev}告警】",
            f"事件类型: {event.event_type}",
            f"攻击分类: {cat}",
            f"信任等级: {event.trust_level}",
            f"拦截阶段: {event.reject_stage or '--'}",
            f"文本摘要: {event.text_preview[:80]}",
            f"时间: {event.timestamp}",
        ]
        return "\n".join(lines)


class DingTalkNotifier(BaseNotifier):
    channel_name = "dingtalk"

    def validate_config(self) -> bool:
        return bool(self.config.get("webhook_url"))

    def send(self, event: AlertEvent) -> bool:
        if not self.validate_config():
            return False
        webhook_url = self.config["webhook_url"]
        secret = self.config.get("secret", "")
        title = f"【玄盾{SEVERITY_LABELS.get(event.severity, '')}告警】{event.attack_category or '拦截'}"
        text = self._format_message(event)

        payload: Dict[str, Any] = {
            "msgtype": "markdown",
            "markdown": {"title": title, "text": text},
        }

        url = webhook_url
        if secret:
            ts = str(round(time.time() * 1000))
            sign_str = f"{ts}\n{secret}"
            sign = base64.b64encode(
                hmac.new(secret.encode("utf-8"), sign_str.encode("utf-8"), hashlib.sha256).digest()
            ).decode("utf-8")
            url = f"{webhook_url}&timestamp={ts}&sign={sign}"

        at_phones = self.config.get("at_phones", [])
        if at_phones:
            payload["at"] = {"atMobiles": at_phones, "isAtAll": False}

        return _post_json(url, payload)


class FeishuNotifier(BaseNotifier):
    channel_name = "feishu"

    def validate_config(self) -> bool:
        return bool(self.config.get("webhook_url"))

    def send(self, event: AlertEvent) -> bool:
        if not self.validate_config():
            return False
        webhook_url = self.config["webhook_url"]
        secret = self.config.get("secret", "")
        sev = SEVERITY_LABELS.get(event.severity, event.severity)

        card = {
            "header": {
                "title": {"tag": "plain_text", "content": f"道体·玄盾 {sev}告警"},
                "template": "red" if event.severity == "critical" else "orange" if event.severity == "important" else "blue",
            },
            "elements": [
                {"tag": "div", "text": {"tag": "lark_md", "content": self._format_message(event)}},
            ],
        }

        payload: Dict[str, Any] = {"msg_type": "interactive", "card": card}

        if secret:
            ts = str(int(time.time()))
            sign_str = f"{ts}\n{secret}"
            sign = base64.b64encode(
                hmac.new(sign_str.encode("utf-8"), b"", hashlib.sha256).digest()
            ).decode("utf-8")
            payload["timestamp"] = ts
            payload["sign"] = sign

        return _post_json(webhook_url, payload)


class EmailNotifier(BaseNotifier):
    channel_name = "email"

    def validate_config(self) -> bool:
        required = ["smtp_host", "smtp_port", "from_addr", "to_addrs"]
        return all(self.config.get(k) for k in required)

    def send(self, event: AlertEvent) -> bool:
        if not self.validate_config():
            return False
        host = self.config["smtp_host"]
        port = int(self.config["smtp_port"])
        user = self.config.get("username", "")
        password = self.config.get("password", "")
        from_addr = self.config["from_addr"]
        to_addrs = self.config["to_addrs"]
        if isinstance(to_addrs, str):
            to_addrs = [to_addrs]
        use_tls = self.config.get("use_tls", True)

        sev = SEVERITY_LABELS.get(event.severity, event.severity)
        subject = f"[{sev}] 道体·玄盾安全告警 - {event.attack_category or '拦截'}"
        body = self._format_message(event)
        body_html = body.replace("\n", "<br>\n")

        msg = f"From: {from_addr}\nTo: {', '.join(to_addrs)}\nSubject: {subject}\nMIME-Version: 1.0\nContent-Type: text/html; charset=utf-8\n\n{body_html}"

        try:
            if use_tls:
                server = smtplib.SMTP_SSL(host, port, timeout=10)
            else:
                server = smtplib.SMTP(host, port, timeout=10)
                server.starttls()
            if user and password:
                server.login(user, password)
            server.sendmail(from_addr, to_addrs, msg.encode("utf-8"))
            server.quit()
            logger.info("Email alert sent to %s", to_addrs)
            return True
        except Exception as e:
            logger.error("Email notifier failed: %s", e)
            return False


class WebhookNotifier(BaseNotifier):
    channel_name = "webhook"

    def validate_config(self) -> bool:
        return bool(self.config.get("webhook_url"))

    def send(self, event: AlertEvent) -> bool:
        if not self.validate_config():
            return False
        webhook_url = self.config["webhook_url"]
        headers = self.config.get("headers", {})
        body_template = self.config.get("body_template", "")

        if body_template:
            body = body_template
            for key, val in event.to_dict().items():
                body = body.replace(f"${{{key}}}", str(val) if val is not None else "")
        else:
            body = json.dumps(event.to_dict(), ensure_ascii=False)

        max_retries = 3
        delays = [1, 4, 16]
        for attempt in range(max_retries):
            ok = _post_json(webhook_url, json.loads(body) if body.startswith("{") else {"body": body}, headers=headers)
            if ok:
                return True
            if attempt < max_retries - 1:
                logger.warning("Webhook attempt %d failed, retrying in %ds", attempt + 1, delays[attempt])
                time.sleep(delays[attempt])
            else:
                logger.error("Webhook notifier failed after %d retries", max_retries)
        return False


class SyslogNotifier(BaseNotifier):
    channel_name = "syslog"

    FACILITY_MAP = {
        "local0": 16 * 8, "local1": 17 * 8, "local2": 18 * 8,
        "local3": 19 * 8, "local4": 20 * 8, "local5": 21 * 8,
        "local6": 22 * 8, "local7": 23 * 8,
    }
    SEVERITY_MAP = {"critical": 2, "important": 4, "info": 6}

    def validate_config(self) -> bool:
        return bool(self.config.get("host")) and bool(self.config.get("port"))

    def send(self, event: AlertEvent) -> bool:
        if not self.validate_config():
            return False
        host = self.config["host"]
        port = int(self.config["port"])
        protocol = self.config.get("protocol", "udp")
        facility = self.config.get("facility", "local0")
        facility_code = self.FACILITY_MAP.get(facility, 16 * 8)
        severity_code = self.SEVERITY_MAP.get(event.severity, 6)
        priority = facility_code + severity_code

        timestamp = event.timestamp
        hostname = socket.gethostname() or "localhost"
        app_name = "xuandun"
        procid = str(os.getpid()) if (os := __import__("os")) else "0"
        msg_id = event.event_type
        structured = f'[xuandun@daoti event="{event.event_type}" category="{event.attack_category or ""}" trust="{event.trust_level}" stage="{event.reject_stage or ""}" severity="{event.severity}"]'
        msg = f"检测到{event.attack_category or '攻击'} - 信任等级:{event.trust_level}"

        syslog_msg = f"<{priority}>1 {timestamp} {hostname} {app_name} {procid} {msg_id} {structured} {msg}"

        try:
            if protocol.lower() == "tcp":
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((host, port))
                sock.sendall((syslog_msg + "\n").encode("utf-8"))
                sock.close()
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.sendto(syslog_msg.encode("utf-8"), (host, port))
                sock.close()
            logger.info("Syslog alert sent to %s:%d/%s", host, port, protocol)
            return True
        except Exception as e:
            logger.error("Syslog notifier failed: %s", e)
            return False


def _post_json(url: str, payload: dict, headers: Optional[dict] = None) -> bool:
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = url_request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json; charset=utf-8")
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    try:
        with url_request.urlopen(req, timeout=10) as resp:
            return resp.status == 200
    except URLError as e:
        logger.error("POST %s failed: %s", url, e)
        return False
    except Exception as e:
        logger.error("POST %s error: %s", url, e)
        return False
