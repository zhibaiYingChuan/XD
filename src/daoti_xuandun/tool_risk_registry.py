"""
MCP/Agent 工具调用安全检测 — 高风险工具意图识别

设计原则（三大支柱 §二）:
  - 检测的本质是"工具调用意图识别"，而非工具本身
  - 基于五行生克意图检测体系，分析用户真实意图
  - 语言无关、工具无关——检测的是意图方向，不是工具名匹配

四类高风险操作:
  1. FILE_RW      文件系统读写（读敏感文件 / 写可执行文件 / 删除系统文件）
  2. NETWORK      网络请求（SSRF / 数据外泄 / C2通信）
  3. CODE_EXEC    代码执行（shell命令 / eval / 动态加载）
  4. CREDENTIAL   凭据访问（环境变量 / 密钥文件 / 系统配置）
"""
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Set, Tuple


class RiskCategory(Enum):
    FILE_RW = "file_rw"
    NETWORK = "network"
    CODE_EXEC = "code_exec"
    CREDENTIAL = "credential"


@dataclass
class SensitiveTool:
    name: str
    risk_category: RiskCategory
    risk_level: float
    description: str = ""
    argument_risks: Dict[str, float] = field(default_factory=dict)
    intent_conditions: Dict[str, Tuple[str, float]] = field(default_factory=dict)


SENSITIVE_TOOLS: List[SensitiveTool] = [

    # FILE_RW: 文件系统读写
    SensitiveTool("fs_read_file", RiskCategory.FILE_RW, 0.55, "读取文件内容",
                  argument_risks={"path": 0.3}, intent_conditions={"technical_malice": ("gt", 0.2)}),
    SensitiveTool("fs_write_file", RiskCategory.FILE_RW, 0.65, "写入文件内容",
                  argument_risks={"path": 0.3, "content": 0.2}, intent_conditions={"technical_malice": ("gt", 0.15)}),
    SensitiveTool("fs_delete_file", RiskCategory.FILE_RW, 0.85, "删除文件",
                  argument_risks={"path": 0.4}, intent_conditions={"technical_malice": ("gt", 0.1)}),
    SensitiveTool("fs_list_directory", RiskCategory.FILE_RW, 0.40, "列出目录内容",
                  argument_risks={"path": 0.3}),
    SensitiveTool("fs_move_file", RiskCategory.FILE_RW, 0.60, "移动/重命名文件",
                  argument_risks={"source": 0.2, "destination": 0.3}),

    # NETWORK: 网络请求
    SensitiveTool("fetch", RiskCategory.NETWORK, 0.65, "发起HTTP请求",
                  argument_risks={"url": 0.5}, intent_conditions={"technical_malice": ("gt", 0.2)}),
    SensitiveTool("http_request", RiskCategory.NETWORK, 0.65, "通用HTTP请求",
                  argument_risks={"url": 0.5, "method": 0.1, "body": 0.3}, intent_conditions={"technical_malice": ("gt", 0.2)}),
    SensitiveTool("websocket_connect", RiskCategory.NETWORK, 0.55, "建立WebSocket连接",
                  argument_risks={"url": 0.4}),
    SensitiveTool("download_file", RiskCategory.NETWORK, 0.60, "下载文件",
                  argument_risks={"url": 0.5, "destination": 0.2}),

    # CODE_EXEC: 代码执行
    SensitiveTool("execute_command", RiskCategory.CODE_EXEC, 0.90, "执行系统命令",
                  argument_risks={"command": 0.6}, intent_conditions={"technical_malice": ("gt", 0.1)}),
    SensitiveTool("eval", RiskCategory.CODE_EXEC, 0.95, "动态执行代码",
                  argument_risks={"code": 0.6}, intent_conditions={"technical_malice": ("gt", 0.05)}),
    SensitiveTool("exec_python", RiskCategory.CODE_EXEC, 0.85, "执行Python代码",
                  argument_risks={"code": 0.5}, intent_conditions={"technical_malice": ("gt", 0.1)}),
    SensitiveTool("exec_bash", RiskCategory.CODE_EXEC, 0.90, "执行Shell命令",
                  argument_risks={"command": 0.6}, intent_conditions={"technical_malice": ("gt", 0.1)}),
    SensitiveTool("subprocess_run", RiskCategory.CODE_EXEC, 0.80, "创建子进程",
                  argument_risks={"args": 0.5}),

    # CREDENTIAL: 凭据访问
    SensitiveTool("read_env", RiskCategory.CREDENTIAL, 0.70, "读取环境变量",
                  argument_risks={"name": 0.4}, intent_conditions={"self_referential": ("gt", 0.3)}),
    SensitiveTool("get_secret", RiskCategory.CREDENTIAL, 0.85, "获取密钥/凭据",
                  argument_risks={"key": 0.5}, intent_conditions={"technical_malice": ("gt", 0.2)}),
    SensitiveTool("read_config", RiskCategory.CREDENTIAL, 0.60, "读取系统配置",
                  argument_risks={"path": 0.3}, intent_conditions={"self_referential": ("gt", 0.25)}),
    SensitiveTool("db_query", RiskCategory.CREDENTIAL, 0.55, "执行数据库查询",
                  argument_risks={"sql": 0.4}),

    # 通配符兜底
    SensitiveTool("*shell*", RiskCategory.CODE_EXEC, 0.75, "匹配Shell类工具"),
    SensitiveTool("*sudo*", RiskCategory.CODE_EXEC, 0.90, "匹配sudo权限工具"),
    SensitiveTool("*admin*", RiskCategory.CREDENTIAL, 0.70, "匹配管理员类工具"),
]


def match_tool(tool_name: str) -> Optional[SensitiveTool]:
    for tool in SENSITIVE_TOOLS:
        if tool.name == tool_name:
            return tool
    for tool in SENSITIVE_TOOLS:
        if "*" in tool.name and tool.name.replace("*", "") in tool_name.lower():
            return tool
    return None


def get_risk_category_name(category: RiskCategory) -> str:
    return {
        RiskCategory.FILE_RW: "文件系统操作",
        RiskCategory.NETWORK: "网络请求",
        RiskCategory.CODE_EXEC: "代码执行",
        RiskCategory.CREDENTIAL: "凭据访问",
    }.get(category, "未知")
