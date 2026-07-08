# 道体·玄盾 桌面端应用 PRD

## 1. 概览

| 字段 | 值 |
|------|-----|
| 产品名称 | 道体·玄盾 桌面安全守护 (Daoti XuanDun Desktop Guard) |
| 版本 | v1.0 |
| 状态 | Draft → Review |
| 负责人 | 道体团队 |
| 日期 | 2026-06-13 |

## 2. 问题陈述

### 2.1 现状

道体·玄盾当前以 **Python 库 + HTTP API 服务** 形态交付，存在以下痛点：

| 痛点 | 影响 | 受影响用户 |
|------|------|-----------|
| **部署门槛高** | 需 Python 环境、pip install、手动启动服务 | 非技术用户、企业安全团队 |
| **集成方式受限** | 仅支持 Flask/FastAPI HTTP 调用，需业务代码主动集成 | IDE 插件开发者、Agent 系统开发者 |
| **无可视化界面** | 无法直观查看防护状态、历史记录、实时告警 | 安全运维人员、管理层 |
| **单一进程模式** | 无系统级驻留能力，需手动维护服务生命周期 | 所有用户 |
| **无反逆向保护** | Python 源码可直接阅读，核心算法暴露 | 商业化场景 |

### 2.2 目标用户

| 用户类型 | 典型场景 | 核心诉求 |
|---------|---------|---------|
| **桌面 Agent 用户** | 使用 Cursor、Windsurf、Claude Desktop、ChatGPT Desktop 等 AI Agent | 一键启用安全防护，无需编程 |
| **企业安全团队** | 管理组织内所有 AI Agent 的安全策略 | 集中管控、审计日志、策略下发 |
| **AI 应用开发者** | 开发桌面端 AI 应用/Agent | SDK 集成、低延迟本地调用 |
| **安全研究人员** | 测试 AI 系统安全边界 | 可视化分析、攻击热力图 |

### 2.3 核心洞察

> **AI Agent 正从云端走向桌面，但桌面端缺乏统一的安全防护层。**

当前 AI Agent 生态的关键趋势：
- Cursor、Windsurf、Claude Desktop 等 IDE/Agent 将 AI 能力直接嵌入桌面
- Agent 系统拥有文件系统、终端、网络等本地资源访问权限
- 恶意提示注入在桌面端的危害远超云端（可执行任意命令）
- **没有任何一款桌面级产品为 Agent 系统提供实时安全防护**

道体·玄盾桌面端应用的定位：**桌面端 Agent 系统的通用安全守护进程**。

## 3. 产品愿景与目标

### 3.1 产品愿景

> 让每一台运行 AI Agent 的桌面电脑，都有一道看不见的盾。

### 3.2 商业目标

| 目标 | 衡量指标 | 目标值 |
|------|---------|-------|
| 降低使用门槛 | 从安装到首次防护的步骤数 | ≤ 3 步 |
| 扩大覆盖范围 | 支持的桌面 Agent 系统数 | ≥ 10 款 |
| 商业化验证 | 付费用户转化率 | ≥ 5% |
| 安全有效性 | 攻击拒绝率（raucle-bench） | ≥ 90% |

### 3.3 用户目标

| 用户目标 | 成功标准 |
|---------|---------|
| 一键安装即用 | 双击安装包 → 选择防护模式 → 立即生效 |
| 全局 Agent 覆盖 | 自动检测并守护所有运行中的 Agent 进程 |
| 零感知防护 | 正常使用无感知，仅在拦截时提示 |
| 可视化监控 | 实时查看防护状态、拦截历史、安全评分 |

## 4. 用户故事

### 4.1 P0 — 必须有（MVP）

**US-01: 一键安装与启动**
> 作为桌面 Agent 用户，我想要双击安装包即可完成安装并启动防护，这样我无需配置 Python 环境或手动启动服务。

验收标准：
- Given 用户下载安装包，When 双击运行，Then 安装完成并在系统托盘显示盾牌图标
- Given 安装完成，When 首次启动，Then 显示防护模式选择界面（高安全/平衡/低误报）
- Given 选择防护模式，When 确认，Then 防护立即生效，系统托盘图标变为"守护中"状态

**US-02: 本地 API 代理模式**
> 作为 AI 应用开发者，我想要桌面应用在本地启动一个 HTTP API 服务，这样我的 Agent 应用可以通过 localhost 调用安全检查。

验收标准：
- Given 桌面应用运行中，When Agent 向 `http://localhost:18765/protect` 发送 POST 请求，Then 返回防护结果
- Given 请求包含 `{"text": "...", "session": "..."}`, When 调用成功，Then 返回 `{"allowed": bool, "trust_level": str, "reject_stage": str|null}`
- Given API 服务异常，When Agent 发送请求，Then 3秒内返回降级响应（默认放行 + 告警日志）

**US-03: Agent 进程自动发现**
> 作为桌面 Agent 用户，我想要应用自动检测运行中的 AI Agent 进程，这样我无需手动配置每个 Agent 的连接。

验收标准：
- Given 桌面应用运行中，When 检测到已知 Agent 进程（Cursor、Claude Desktop 等），Then 在界面显示已发现的 Agent 列表
- Given 发现新 Agent 进程，When Agent 发出 HTTP 请求，Then 自动应用防护策略
- Given Agent 进程退出，When 不再检测到进程，Then 从活跃列表移除

**US-04: 系统级流量拦截**
> 作为桌面 Agent 用户，我想要应用在系统层面拦截 Agent 的网络请求，这样即使 Agent 不主动调用 API 也能获得防护。

验收标准：
- Given 启用流量拦截模式，When Agent 向 LLM API 发送请求，Then 请求经过玄盾检查
- Given 请求包含恶意提示注入，When 检测到攻击，Then 拦截请求并通知用户
- Given 请求为正常内容，When 检测通过，Then 请求正常转发，延迟增加 < 10ms

**US-05: 拦截通知与日志**
> 作为桌面 Agent 用户，我想要在攻击被拦截时收到桌面通知，这样我能及时了解安全事件。

验收标准：
- Given 攻击被拦截，When 拦截发生，Then 系统托盘弹出通知（含攻击类型、风险等级）
- Given 用户点击通知，When 打开主界面，Then 显示该拦截事件的详细信息
- Given 拦截历史，When 查看日志面板，Then 按时间倒序展示所有拦截/放行记录

### 4.2 P1 — 应该有

**US-06: 防护模式切换**
> 作为用户，我想要随时切换防护模式（高安全/平衡/低误报），这样我可以根据场景调整安全强度。

**US-07: 领域自适应预热**
> 作为用户，我想要导入我的业务领域文本来预热防护系统，这样系统对专业术语的误判率更低。

**US-08: 安全仪表盘**
> 作为安全运维人员，我想要一个可视化仪表盘展示防护统计，这样我可以评估安全态势。

**US-09: Agent 白名单/黑名单**
> 作为用户，我想要为不同 Agent 设置不同的防护策略，这样我可以对高权限 Agent 使用更严格的防护。

### 4.3 P2 — 可以有

**US-10: 多设备同步**
> 作为企业用户，我想要在多台设备间同步防护策略，这样我无需逐台配置。

**US-11: 攻击热力图**
> 作为安全研究人员，我想要可视化攻击类型分布和趋势，这样我可以研究攻击模式。

**US-12: 自定义规则引擎**
> 作为高级用户，我想要添加自定义检测规则，这样我可以针对特定场景优化检测。

## 5. 功能需求

### 5.1 核心防护引擎（P0）

| 功能 | 描述 | 优先级 |
|------|------|--------|
| 本地 HTTP API 服务 | 在 localhost:18765 启动 RESTful API，兼容现有 Flask/FastAPI 接口 | P0 |
| 四阶段防护流水线 | 内生域感知 → 动态阴阳壳 → 自组织符号映射 → 时序一致性校验 | P0 |
| 防护模式预设 | high_security / balanced / low_false_positive 三种模式 | P0 |
| 会话管理 | 自动为每个 Agent 连接分配独立会话 | P0 |
| 领域自适应 | 支持导入领域文本进行预热 | P0 |

### 5.2 桌面端交互（P0）

| 功能 | 描述 | 优先级 |
|------|------|--------|
| 系统托盘驻留 | 最小化到系统托盘，盾牌图标指示防护状态 | P0 |
| 首次启动向导 | 引导用户选择防护模式、配置 Agent 连接 | P0 |
| 拦截通知 | 攻击被拦截时弹出系统通知 | P0 |
| 主控面板 | 显示防护状态、Agent 列表、实时统计 | P0 |
| 日志查看器 | 按时间/类型/Agent 筛选的拦截/放行日志 | P0 |

### 5.3 Agent 集成（P0）

| 功能 | 描述 | 优先级 |
|------|------|--------|
| 进程自动发现 | 扫描已知 Agent 进程（Cursor、Claude Desktop、Windsurf 等） | P0 |
| HTTP API 代理 | 本地 HTTP 服务供 Agent 主动调用 | P0 |
| 系统流量拦截 | 可选：通过本地代理拦截 Agent 的 LLM API 请求 | P0 |
| MCP 协议支持 | 作为 MCP Server 暴露 `protect` 工具，供 MCP 兼容 Agent 调用 | P0 |

### 5.4 安全与保密（P0）

| 功能 | 描述 | 优先级 |
|------|------|--------|
| 反逆向工程 | 代码混淆、二进制打包、反调试、反内存转储 | P0 |
| 密钥保护 | 运行时密钥不出明文，使用操作系统密钥库 | P0 |
| 安全通信 | 本地 API 仅监听 localhost，TLS 可选 | P0 |
| 审计日志 | 不可篡改的防护操作日志 | P0 |

### 5.5 高级功能（P1/P2）

| 功能 | 描述 | 优先级 |
|------|------|--------|
| 策略管理界面 | 可视化配置防护参数、阈值调整 | P1 |
| 安全仪表盘 | 攻击拦截率、误报率、趋势图 | P1 |
| Agent 策略分组 | 为不同 Agent/Agent 组设置不同防护策略 | P1 |
| 多设备策略同步 | 通过云端同步防护策略（端到端加密） | P2 |
| 攻击热力图 | 可视化攻击类型分布和时序趋势 | P2 |
| 自定义规则引擎 | 用户自定义检测规则（正则/关键词/统计） | P2 |

## 6. 支持的桌面 Agent 系统

### 6.1 首批支持（MVP）

| Agent 系统 | 集成方式 | 优先级 |
|-----------|---------|--------|
| **Cursor** | HTTP API + 进程发现 | P0 |
| **Claude Desktop** | MCP Server + HTTP API | P0 |
| **Windsurf** | HTTP API + 进程发现 | P0 |
| **ChatGPT Desktop** | HTTP API + 流量拦截 | P0 |
| **VS Code + Continue** | HTTP API + VS Code 扩展 | P0 |

### 6.2 扩展支持（P1）

| Agent 系统 | 集成方式 | 优先级 |
|-----------|---------|--------|
| **Cline (VS Code)** | HTTP API + VS Code 扩展 | P1 |
| **Aider** | HTTP API + CLI 集成 | P1 |
| **Open Interpreter** | HTTP API + 进程发现 | P1 |
| **AutoGPT Desktop** | HTTP API + 流量拦截 | P1 |
| **任意 MCP 兼容 Agent** | MCP Server | P1 |

### 6.3 通用集成协议

桌面应用提供三种集成方式，覆盖所有桌面 Agent 系统：

1. **HTTP API（主动调用）**：Agent 主动调用 `localhost:18765/protect`
2. **MCP Server（协议级集成）**：作为 MCP Server 暴露 `xuandun_protect` 工具
3. **流量拦截（透明代理）**：通过本地代理自动拦截 Agent 的 LLM API 请求

## 7. 技术架构

### 7.1 整体架构

```
┌─────────────────────────────────────────────────────────┐
│                  桌面端应用 (Tauri)                       │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────────┐   │
│  │ 系统托盘  │  │ 主控面板  │  │    设置/日志面板      │   │
│  └──────────┘  └──────────┘  └──────────────────────┘   │
│                    ↕ IPC ↕                                │
│  ┌─────────────────────────────────────────────────────┐ │
│  │              Rust 核心服务层                          │ │
│  │  ┌─────────┐ ┌──────────┐ ┌─────────────────────┐  │ │
│  │  │进程发现  │ │流量拦截   │ │  通知/日志管理       │  │ │
│  │  └─────────┘ └──────────┘ └─────────────────────┘  │ │
│  │  ┌─────────┐ ┌──────────┐ ┌─────────────────────┐  │ │
│  │  │HTTP API │ │MCP Server│ │  密钥/配置管理       │  │ │
│  │  └─────────┘ └──────────┘ └─────────────────────┘  │ │
│  └─────────────────────┬───────────────────────────────┘ │
│                        ↕ Sidecar IPC                      │
│  ┌─────────────────────┴───────────────────────────────┐ │
│  │           Python 防护引擎 (PyInstaller/Nuitka)       │ │
│  │  ┌──────────────────────────────────────────────┐   │ │
│  │  │  XuanDun Core (reject_gate + dynamic_shell   │   │ │
│  │  │  + ancient_mapper + luoshu + timing_checker) │   │ │
│  │  └──────────────────────────────────────────────┘   │ │
│  └─────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
         ↕                    ↕                   ↕
    ┌─────────┐        ┌──────────┐        ┌──────────┐
    │ Cursor  │        │ Claude   │        │ Windsurf │
    │ (HTTP)  │        │ (MCP)    │        │ (HTTP)   │
    └─────────┘        └──────────┘        └──────────┘
```

### 7.2 技术选型

| 组件 | 技术选择 | 理由 |
|------|---------|------|
| **桌面框架** | Tauri 2.0 | 轻量（< 10MB）、Rust 安全性、跨平台、原生性能 |
| **前端 UI** | React + TypeScript + TailwindCSS | 生态成熟、组件丰富、Tauri 官方推荐 |
| **核心引擎** | Python (Nuitka 编译) | 复用现有代码、Nuitka 编译为原生二进制（反逆向） |
| **进程通信** | Sidecar (Tauri) + Unix Socket / Named Pipe | 跨语言 IPC、高性能 |
| **MCP Server** | mcp Python SDK | 官方 SDK、stdio 传输 |
| **流量拦截** | Rust + mitmproxy-rs / 透明代理 | 系统级拦截、低延迟 |
| **密钥存储** | OS Keychain (keyring) | 系统级安全存储 |
| **日志存储** | SQLite (本地) | 轻量、查询灵活、不可篡改（WAL 模式） |
| **打包分发** | Tauri bundler + NSIS (Win) / DMG (Mac) / AppImage (Linux) | 原生安装体验 |

### 7.3 Python 引擎封装方案

**选择 Nuitka 而非 PyInstaller 的理由：**

| 维度 | Nuitka | PyInstaller |
|------|--------|-------------|
| 编译方式 | Python → C → 原生二进制 | 字节码打包 + 运行时解压 |
| 反逆向难度 | 高（C 编译后难以反编译） | 低（pyc 可被 uncompyle6 反编译） |
| 启动速度 | 快（原生执行） | 慢（需解压 + 启动解释器） |
| 文件体积 | 较大（含 C 编译产物） | 中等 |
| 兼容性 | 需 C 编译器 | 开箱即用 |

**Sidecar 架构：**
- Python 引擎编译为独立可执行文件 `xuandun-engine.exe`
- Tauri 通过 Sidecar 机制管理引擎进程生命周期
- 引擎启动后监听 Named Pipe，Rust 层通过 Pipe 发送检查请求
- 引擎崩溃时自动重启，保持防护连续性

## 8. 反逆向工程保密计划

### 8.1 威胁模型

| 攻击者 | 能力 | 目标 |
|--------|------|------|
| 普通用户 | 反编译工具、十六进制编辑器 | 理解防护逻辑以绕过 |
| 安全研究员 | 动态调试、内存转储、Fuzzing | 发现算法漏洞 |
| 竞争对手 | 静态分析、逆向工程、代码克隆 | 窃取核心算法 |
| APT 攻击者 | 内核级调试、硬件断点、侧信道 | 完全理解并绕过防护 |

### 8.2 纵深防御体系

#### 第一层：编译期保护

| 措施 | 实施方式 | 防御目标 |
|------|---------|---------|
| **Nuitka 编译** | Python → C → 原生二进制，消除 pyc 字节码 | 防止 uncompyle6/decompyle3 反编译 |
| **符号剥离** | Nuitka `--remove-output` + strip | 移除调试符号、函数名 |
| **控制流混淆** | Nuitka `--lto=yes` + 自定义 C 级混淆 | 增加静态分析难度 |
| **字符串加密** | 运行时解密敏感字符串（密钥、阈值） | 防止字符串搜索定位关键逻辑 |
| **常量折叠** | 编译期计算关键常量 | 避免明文常量暴露 |

#### 第二层：运行时保护

| 措施 | 实施方式 | 防御目标 |
|------|---------|---------|
| **反调试检测** | `IsDebuggerPresent()` + `NtQueryInformationProcess()` + 定时器检测 | 检测 OllyDbg/x64dbg/WinDbg |
| **反内存转储** | 关键内存页 `VirtualProtect(PAGE_GUARD)` + 定期重加密 | 防止 ProcDump/minidump |
| **反注入检测** | 校验模块列表完整性 + 检测未知 DLL | 防止 DLL 注入 hook |
| **完整性自校验** | 启动时校验自身哈希 + 关键段 CRC | 检测二进制篡改 |
| **时序反分析** | 关键路径添加随机延迟 + 时间戳校验 | 防止时序侧信道 |

#### 第三层：算法级保护

| 措施 | 实施方式 | 防御目标 |
|------|---------|---------|
| **密钥派生** | PBKDF2 + 硬件指纹绑定 | 密钥不可提取/不可移植 |
| **白盒密码** | 洛书映射器的密钥以白盒实现嵌入 | 防止密钥提取 |
| **算法分散** | 核心逻辑分散在多个编译单元 | 增加逆向工程工作量 |
| **动态密钥演化** | 运行时密钥随状态演化（动态阴阳壳） | 即使快照也无法还原完整状态 |
| **噪声注入** | 原型距离噪声 + 高维投影扰动 | 防止边界枚举和参数提取 |

#### 第四层：分发保护

| 措施 | 实施方式 | 防御目标 |
|------|---------|---------|
| **代码签名** | EV 代码签名证书 | 防篡改 + 信任链 |
| **运行时校验** | 启动时验证签名链 | 检测重新打包 |
| **在线激活** | 首次运行需联网激活（硬件指纹绑定） | 防止大规模盗版 |
| **自动更新** | 强制安全更新（不可跳过关键补丁） | 修复已知绕过方法 |
| **遥测异常检测** | 检测异常使用模式（大量重复请求等） | 识别自动化逆向行为 |

### 8.3 反逆向实施优先级

| 阶段 | 措施 | 优先级 | 预计工作量 |
|------|------|--------|-----------|
| **MVP** | Nuitka 编译 + 符号剥离 + 字符串加密 + 代码签名 | P0 | 2 周 |
| **V1.1** | 反调试 + 反内存转储 + 完整性自校验 | P0 | 2 周 |
| **V1.2** | 白盒密码 + 算法分散 + 密钥硬件绑定 | P1 | 3 周 |
| **V2.0** | 在线激活 + 遥测异常检测 + 动态混淆 | P2 | 4 周 |

### 8.4 安全开发生命周期

```
设计阶段 → 威胁建模（STRIDE）→ 安全需求 → 安全设计评审
    ↓
编码阶段 → 安全编码规范 → 代码审查 → SAST 扫描
    ↓
构建阶段 → Nuitka 编译 → 符号剥离 → 代码签名 → 完整性校验
    ↓
测试阶段 → 渗透测试 → 逆向工程演练 → 漏洞修复
    ↓
发布阶段 → 签名验证 → 自动更新 → 遥测监控
```

## 9. 非功能需求

### 9.1 性能

| 指标 | 目标值 | 测量方法 |
|------|--------|---------|
| 单次防护检查延迟（STANDARD 模式） | ≤ 10ms (p99) | 本地 HTTP API 端到端 |
| 内存占用（空闲） | ≤ 150MB | 进程监控 |
| 内存占用（高负载） | ≤ 500MB | 1000 QPS 持续 10 分钟 |
| CPU 占用（空闲） | ≤ 1% | 进程监控 |
| 启动时间 | ≤ 3s | 双击图标到托盘图标出现 |
| API 吞吐量 | ≥ 500 QPS (4核8G) | wrk 压测 |

### 9.2 安全

| 需求 | 描述 |
|------|------|
| 本地 API 仅监听 localhost | 禁止外部网络访问 API 端口 |
| TLS 可选 | 企业部署可启用 TLS |
| 审计日志不可篡改 | SQLite WAL + 哈希链校验 |
| 敏感数据不落盘 | 运行时密钥仅存在于内存，退出即清除 |
| 最小权限原则 | 不请求不必要的系统权限 |

### 9.3 可用性

| 需求 | 描述 |
|------|------|
| 跨平台 | Windows 10+、macOS 12+、Ubuntu 22.04+ |
| 无 Python 依赖 | 用户无需安装 Python |
| 自动更新 | 后台检测并安装更新 |
| 优雅降级 | 引擎崩溃时 API 返回降级响应（放行 + 告警） |
| 多语言 | 中文、英文 |

### 9.4 可靠性

| 需求 | 描述 |
|------|------|
| 引擎自动重启 | Sidecar 崩溃后 5s 内自动重启 |
| 数据持久化 | 防护配置、预热数据、日志不因重启丢失 |
| 原子配置更新 | 配置变更不会导致中间状态 |

## 10. 技术约束与风险

### 10.1 技术约束

| 约束 | 影响 | 缓解措施 |
|------|------|---------|
| Python GIL | 高并发下 API 吞吐受限 | 多进程 Sidecar + 异步 IO |
| Nuitka 编译兼容性 | 部分 Python 动态特性可能不兼容 | 提前测试 + 代码适配 |
| 流量拦截权限 | macOS/Linux 需 root 权限 | 提供可选模式，默认仅 HTTP API |
| Tauri Sidecar 体积 | Python 引擎编译后约 30-50MB | UPX 压缩 + 按需下载 |

### 10.2 风险评估

| 风险 | 概率 | 影响 | 缓解措施 |
|------|------|------|---------|
| Nuitka 编译失败 | 中 | 高 | 提前验证所有核心模块；备选 PyInstaller + 加密 |
| 流量拦截被杀毒软件误报 | 高 | 中 | 代码签名 + 白名单申请 + 可选禁用 |
| Agent 进程发现不完整 | 中 | 低 | 支持手动添加 + 配置文件导入 |
| 反逆向措施影响性能 | 低 | 中 | 性能基准测试 + 可配置安全级别 |
| 跨平台兼容性问题 | 中 | 中 | CI 多平台测试 + 社区反馈 |

## 11. 里程碑与交付计划

### Phase 1: MVP（6 周）

| 周次 | 交付物 | 验收标准 |
|------|--------|---------|
| W1-W2 | Tauri 项目脚手架 + Python 引擎 Nuitka 编译 | 双击启动，系统托盘驻留 |
| W2-W3 | 本地 HTTP API + 进程发现 | Agent 可通过 localhost 调用防护 |
| W3-W4 | 主控面板 + 拦截通知 + 日志查看 | 用户可查看防护状态和拦截历史 |
| W4-W5 | MCP Server 集成 + 反逆向（MVP 级） | Claude Desktop 可通过 MCP 调用 |
| W5-W6 | 集成测试 + 安装包构建 + 文档 | Windows 安装包可正常安装运行 |

### Phase 2: V1.0（4 周）

| 周次 | 交付物 | 验收标准 |
|------|--------|---------|
| W7-W8 | 流量拦截模式 + 反逆向（V1.1 级） | 透明拦截 Agent LLM 请求 |
| W8-W9 | 安全仪表盘 + 策略管理 | 可视化防护统计 + 参数调整 |
| W9-W10 | macOS/Linux 适配 + 多语言 | 三平台安装包 |

### Phase 3: V1.5（4 周）

| 周次 | 交付物 | 验收标准 |
|------|--------|---------|
| W11-W12 | 白盒密码 + 算法分散 + 密钥硬件绑定 | 反逆向达到 V1.2 级 |
| W12-W13 | Agent 策略分组 + 扩展 Agent 支持 | 支持 10+ Agent 系统 |
| W13-W14 | 性能优化 + 稳定性测试 | p99 延迟 < 10ms |

## 12. 成功指标（KPI）

| 指标 | MVP 目标 | V1.0 目标 | V1.5 目标 |
|------|---------|----------|----------|
| 安装成功率 | ≥ 95% | ≥ 98% | ≥ 99% |
| 攻击拒绝率（raucle-bench） | ≥ 85% | ≥ 90% | ≥ 92% |
| 良性接纳率（raucle-bench） | ≥ 80% | ≥ 85% | ≥ 88% |
| API 延迟 p99 | ≤ 15ms | ≤ 10ms | ≤ 8ms |
| 逆向工程耗时（评估） | ≥ 2 人周 | ≥ 1 人月 | ≥ 3 人月 |
| 支持 Agent 数 | 5 | 8 | 12+ |
| 用户 NPS | ≥ 30 | ≥ 50 | ≥ 60 |

## 13. 开放问题

| # | 问题 | 状态 | 负责人 |
|---|------|------|--------|
| 1 | Nuitka 对 numpy/torch 的编译兼容性验证 | 待验证 | 工程 |
| 2 | 流量拦截在 macOS 上的权限方案 | 待调研 | 工程 |
| 3 | MCP Server 的 stdio 传输与 Tauri Sidecar 的集成方式 | 待设计 | 工程 |
| 4 | 白盒密码实现的性能影响评估 | 待测试 | 安全 |
| 5 | 在线激活服务的架构设计 | 待设计 | 产品 |
| 6 | 企业版 vs 个人版的功能边界 | 待定义 | 产品 |

## 14. 附录

### A. API 接口规范

#### A.1 HTTP API

```
POST /protect
Content-Type: application/json

Request:
{
  "text": "string (required)",
  "session": "string (optional, default: auto)",
  "mode": "high_security|balanced|low_false_positive (optional)"
}

Response 200:
{
  "allowed": boolean,
  "trust_level": "HIGH|MEDIUM|LOW|UNKNOWN",
  "reject_stage": "reject_gate|timing_checker|null",
  "domain_distance": float,
  "timing_distance": float
}

Response 503 (引擎不可用):
{
  "allowed": true,
  "trust_level": "UNKNOWN",
  "fallback": true,
  "message": "Security engine unavailable, request passed with warning"
}
```

#### A.2 MCP Tool

```
Tool: xuandun_protect
Description: 检查输入文本是否包含恶意提示注入或越狱攻击

Parameters:
  text (string, required): 要检查的文本
  session (string, optional): 会话标识
  mode (string, optional): 防护模式

Returns:
  allowed: boolean
  trust_level: string
  reject_stage: string|null
```

#### A.3 进程发现规则

```json
{
  "agents": [
    {"name": "Cursor", "process": ["cursor.exe", "Cursor"], "port_hint": null},
    {"name": "Claude Desktop", "process": ["claude.exe", "Claude"], "port_hint": null},
    {"name": "Windsurf", "process": ["windsurf.exe", "Windsurf"], "port_hint": null},
    {"name": "ChatGPT Desktop", "process": ["chatgpt.exe", "ChatGPT"], "port_hint": null},
    {"name": "VS Code + Continue", "process": ["code.exe", "Code"], "extension_hint": "continue"}
  ]
}
```

### B. 反逆向工程详细技术方案

#### B.1 Nuitka 编译配置

```bash
python -m nuitka \
  --standalone \
  --onefile \
  --remove-output \
  --lto=yes \
  --strip \
  --windows-icon-from-ico=assets/shield.ico \
  --windows-company-name="Daoti" \
  --windows-product-name="XuanDun Engine" \
  --windows-file-version=1.0.0 \
  --enable-plugin=numpy \
  --nofollow-import-to=tkinter \
  --nofollow-import-to=test \
  --output-filename=xuandun-engine \
  src/daoti_xuandun/engine_main.py
```

#### B.2 字符串加密实现

```python
import base64
import os

class _SecureString:
    _key = None

    @classmethod
    def _get_key(cls):
        if cls._key is None:
            cls._key = os.urandom(32)
        return cls._key

    @classmethod
    def encrypt(cls, plaintext: str) -> str:
        key = cls._get_key()
        data = plaintext.encode('utf-8')
        xored = bytes(a ^ b for a, b in zip(data, key[:len(data)]))
        return base64.b64encode(xored).decode('ascii')

    @classmethod
    def decrypt(cls, ciphertext: str) -> str:
        key = cls._get_key()
        xored = base64.b64decode(ciphertext)
        data = bytes(a ^ b for a, b in zip(xored, key[:len(xored)]))
        return data.decode('utf-8')
```

#### B.3 反调试检测（Windows）

```c
// anti_debug.c - Nuitka 编译时链接
#include <windows.h>
#include <winternl.h>

int check_debugger() {
    if (IsDebuggerPresent()) return 1;

    BOOL debugged = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &debugged);
    if (debugged) return 2;

    // NtQueryInformationProcess 检测
    typedef NTSTATUS(NTAPI* pNtQIP)(HANDLE, UINT, PVOID, ULONG, PULONG);
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (ntdll) {
        pNtQIP NtQIP = (pNtQIP)GetProcAddress(ntdll, "NtQueryInformationProcess");
        if (NtQIP) {
            DWORD_PTR debug_port = 0;
            NTSTATUS status = NtQIP(GetCurrentProcess(), 7, &debug_port, sizeof(debug_port), NULL);
            if (status == 0 && debug_port != 0) return 3;
        }
    }
    return 0;
}
```

### C. 工程文化教练监督要点

| 阶段 | 监督要点 | 检查清单 |
|------|---------|---------|
| **设计** | 架构决策记录（ADR） | 每个重大技术选型有 ADR 文档 |
| **编码** | 代码审查 + 安全审查 | PR 必须经过 2 人审查 + 安全审查 |
| **构建** | 可重现构建 | 同一源码 → 同一二进制哈希 |
| **测试** | 测试覆盖率 + 安全测试 | 核心模块覆盖率 ≥ 80% + 渗透测试 |
| **发布** | 发布清单 + 回滚方案 | 每次发布有完整清单和回滚步骤 |
| **运维** | 监控 + 告警 + 事后复盘 | 关键指标有监控，事故有复盘 |
