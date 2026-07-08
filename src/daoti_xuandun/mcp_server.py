"""道体·玄盾 MCP Server。

作为 MCP (Model Context Protocol) Server 运行，
供 Claude Desktop 等 MCP 兼容 Agent 调用。

使用方式（在 Claude Desktop 配置中添加）:
{
  "mcpServers": {
    "xuandun": {
      "command": "python",
      "args": ["-m", "daoti_xuandun.mcp_server"]
    }
  }
}
"""

import json
import sys
import uuid
from typing import Any

from daoti_xuandun import XuanDun, XuanDunConfig, DefenseLevel

_shield: XuanDun = XuanDun(XuanDunConfig.for_level(DefenseLevel.STANDARD))
_shields: dict = {"balanced": _shield}

_TOOL_PROTECT = {
    "name": "xuandun_protect",
    "description": "检查输入文本是否包含恶意提示注入或越狱攻击。在将用户输入发送给 LLM 之前调用此工具进行安全检查。",
    "inputSchema": {
        "type": "object",
        "properties": {
            "text": {
                "type": "string",
                "description": "要检查的文本内容",
            },
            "session": {
                "type": "string",
                "description": "会话标识（可选）",
            },
            "mode": {
                "type": "string",
                "enum": ["high_security", "balanced", "low_false_positive"],
                "description": "防护模式（默认 balanced）",
            },
        },
        "required": ["text"],
    },
}

_TOOL_STATUS = {
    "name": "xuandun_status",
    "description": "获取道体·玄盾防护引擎的运行状态",
    "inputSchema": {
        "type": "object",
        "properties": {},
    },
}


def _send_message(msg: dict) -> None:
    body = json.dumps(msg, ensure_ascii=False)
    sys.stdout.write(f"Content-Length: {len(body.encode('utf-8'))}\r\n\r\n{body}")
    sys.stdout.flush()


def _read_message() -> dict:
    line = sys.stdin.readline()
    if not line:
        return {}
    if line.startswith("Content-Length:"):
        length = int(line.split(":")[1].strip())
        sys.stdin.readline()
        body = sys.stdin.read(length)
        try:
            return json.loads(body)
        except json.JSONDecodeError as e:
            raise ValueError(f"JSON parse error: {e}") from e
    return {}


def _handle_initialize(params: dict) -> dict:
    return {
        "protocolVersion": "2024-11-05",
        "capabilities": {
            "tools": {},
        },
        "serverInfo": {
            "name": "xuandun-mcp-server",
            "version": "1.0.0",
        },
    }


def _handle_tools_list(params: dict) -> dict:
    return {
        "tools": [_TOOL_PROTECT, _TOOL_STATUS],
    }


def _handle_tools_call(params: dict) -> dict:
    name = params.get("name", "")
    arguments = params.get("arguments", {})

    if name == "xuandun_protect":
        text = arguments.get("text", "")
        session = arguments.get("session", str(uuid.uuid4())[:8])
        mode = arguments.get("mode", "balanced")

        if not text:
            return {
                "content": [{"type": "text", "text": "Error: text is required"}],
                "isError": True,
            }

        try:
            level = {
                "high_security": DefenseLevel.STRICT,
                "balanced": DefenseLevel.STANDARD,
                "low_false_positive": DefenseLevel.BASIC,
            }.get(mode, DefenseLevel.STANDARD)

            if mode not in _shields:
                config = XuanDunConfig.for_level(level)
                _shields[mode] = XuanDun(config)
            shield = _shields[mode]
            result = shield.protect(text, session_id=session)

            status = "ALLOWED" if result.allowed else "BLOCKED"
            trust = result.trust_level.value if hasattr(result.trust_level, "value") else str(result.trust_level)

            text_result = f"Security Check: {status}\nTrust Level: {trust}"
            if result.reject_stage:
                text_result += f"\nReject Stage: {result.reject_stage}"
            if result.domain_distance is not None:
                text_result += f"\nDomain Distance: {result.domain_distance:.4f}"

            return {
                "content": [{"type": "text", "text": text_result}],
            }
        except Exception as e:
            return {
                "content": [{"type": "text", "text": f"Error: {str(e)}"}],
                "isError": True,
            }

    elif name == "xuandun_status":
        try:
            import urllib.request
            req = urllib.request.Request("http://localhost:18765/status", method="GET")
            with urllib.request.urlopen(req, timeout=3) as resp:
                engine_status = json.loads(resp.read().decode("utf-8"))
            return {
                "content": [{"type": "text", "text": json.dumps({
                    "status": "Running" if engine_status.get("running") else "Stopped",
                    "mode": engine_status.get("mode", "unknown"),
                    "total_requests": engine_status.get("total_requests", 0),
                    "total_blocked": engine_status.get("total_blocked", 0),
                    "block_rate": f"{engine_status.get('block_rate', 0):.1%}",
                }, ensure_ascii=False)}]
            }
        except Exception as e:
            return {
                "content": [{"type": "text", "text": json.dumps({
                    "status": "Offline",
                    "error": str(e),
                }, ensure_ascii=False)}]
            }

    return {
        "content": [{"type": "text", "text": f"Unknown tool: {name}"}],
        "isError": True,
    }


_HANDLERS = {
    "initialize": _handle_initialize,
    "tools/list": _handle_tools_list,
    "tools/call": _handle_tools_call,
}


def main() -> None:
    while True:
        try:
            msg = _read_message()
            if not msg:
                break

            method = msg.get("method", "")
            params = msg.get("params", {})
            msg_id = msg.get("id")

            if method == "notifications/initialized":
                continue

            if method in _HANDLERS:
                result = _HANDLERS[method](params)
                if msg_id is not None:
                    _send_message({
                        "jsonrpc": "2.0",
                        "id": msg_id,
                        "result": result,
                    })
            elif method == "ping":
                if msg_id is not None:
                    _send_message({
                        "jsonrpc": "2.0",
                        "id": msg_id,
                        "result": {},
                    })
        except ValueError as e:
            sys.stderr.write(f"MCP Server JSON parse error: {e}\n")
            _send_message({
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": f"Parse error: {e}"},
            })
        except Exception as e:
            sys.stderr.write(f"MCP Server error: {e}\n")


if __name__ == "__main__":
    main()
