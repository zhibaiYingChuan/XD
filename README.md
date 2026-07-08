# 道体·玄盾 (Daoti XuanDun)

> **活性防护 LLM 防火墙** — 为 AI 应用提供数据驱动的动态安全防护

道体·玄盾是一个基于"拒绝门理论 + 洛书映射器 + 动态阴阳壳"架构的 LLM 输入检测系统。它不依赖静态规则或签名，而是通过域距离、结构异常、4-gram 统计三重检测，结合在线学习持续增强防御能力。

> ⚠️ **安全声明**：本系统为**活性防护**产品，防御能力随在线学习持续增强。文档中引用的"100%攻击拒绝率"等数据仅反映对**内部基准测试集（200+样本，17类攻击探针）**的统计表现，**不承诺对未知攻击的绝对防御**。实际效果取决于部署环境、预热样本质量和在线学习积累。**安全是过程，不是终点。**

## 核心特性

- **三重检测引擎**：域距离 + 结构/二进制异常 + 4-gram 统计
- **原创理论架构**：拒绝门理论 + 洛书符号映射器 + 动态阴阳壳
- **活性在线学习**：从通过的请求中自动学习，防御能力随使用持续增强
- **反逆向保护**：Nuitka 编译 + 三端 anti_debug + 编译期 key 注入 + 阈值加密
- **三端桌面应用**：Windows / macOS (Apple Silicon + Intel) / Linux
- **会话隔离**：不同会话输出不可关联（汉明距离 > 50%）

## 下载安装

### 桌面端（推荐普通用户）

前往 [Releases](https://github.com/zhibaiYingChuan/xuandun/releases) 下载对应平台的安装包：

| 平台 | 安装包 | 说明 |
|------|--------|------|
| Windows x64 | `道体·玄盾_1.0.0_x64-setup.exe` | NSIS 安装程序，支持中英文 |
| macOS (Apple Silicon) | `道体·玄盾_1.0.0_aarch64.dmg` | M1/M2/M3 芯片 |
| macOS (Intel) | `道体·玄盾_1.0.0_x64.dmg` | Intel 芯片 |
| Linux x64 | `道体·玄盾_1.0.0_amd64.AppImage` | 便携版，无需安装 |
| Linux x64 | `道体·玄盾_1.0.0_amd64.deb` | Debian/Ubuntu 包管理 |

> **macOS 用户注意**：DMG 未签名（待 Apple Developer ID 申请后签名），首次打开需在"系统设置 > 隐私与安全性"中点击"仍要打开"。

### Python SDK（开发者集成）

```bash
pip install -e .
```

## 30秒开箱即用

### 方式1：零代码体验

```python
from daoti_xuandun import XuanDun

shield = XuanDun()                # 使用默认 balanced 模式
result = shield.protect("用户输入")
print(result.allowed, result.trust_level)
```

### 方式2：交互式向导（推荐新手）

```bash
python -m daoti_xuandun.setup
```

### 方式3：挑战赛 API

```bash
python -m daoti_xuandun.challenge_api --port 8080
```

访问 `http://localhost:8080/challenge` 提交文本测试防护效果。

## 简化模式

```python
# 高安全模式 — 优先拦截攻击，宁可误报不可漏报
shield = XuanDun(mode="high_security")

# 平衡模式 — 安全与体验兼顾（默认）
shield = XuanDun(mode="balanced")

# 低误报模式 — 优先减少误判，适合内部工具
shield = XuanDun(mode="low_false_positive")
```

## 场景化配置速查表

| 应用场景 | 推荐 mode | 预期误报风险 |
|---------|-----------|-------------|
| 医疗病历分析 | `high_security` | 医学术语可能误判（提供更多样本可缓解） |
| 金融客服 | `high_security` + `enable_timing_check=True` | 合法重复查询可能被时序校验告警 |
| 教育/学术问答 | `balanced` | 安全研究问题可能被误拒 |
| 代码生成助手 | `high_security` | 代码注释中的攻击示例可能被拦截 |
| 内部工具/个人助理 | `low_false_positive` | 极少误判，但防护较弱 |

详细场景配置示例见 [docs/白皮书.md](docs/白皮书.md)。

## 架构

道体·玄盾采用"道体（I）+ LLM（感官）"哲学设计：

```
用户输入
   ↓
[洛书映射器] — Unicode 码点 → 64卦原型空间（语言无关）
   ↓
[动态阴阳壳] — 阴阳光融合 → 高熵状态向量
   ↓
[拒绝门] — 域距离 + 结构异常 + 4-gram → 允许/拒绝
   ↓
[在线学习] — 通过的请求自动扩展域知识
```

核心组件：
- **洛书映射器** (`luoshu_mapper.py`)：将任意输入映射到64卦原型空间，通过原型距离判断"域内/域外/攻击"
- **动态阴阳壳** (`dynamic_shell.py`)：状态依赖权重演化 + 混沌非零偏置，任何输入都产生高熵输出
- **拒绝门** (`reject_gate.py`)：三重检测融合决策，支持四级防御层级（BASIC/STANDARD/STRICT/PARANOID）
- **时序校验** (`timing_checker.py`)：检测重复/模式化攻击
- **自组织符号映射** (`ancient_mapper.py`)：符号边界动态调整，攻击者无法建立静态逆映射

## 性能基准

### 实测数据（balanced模式 + 英文预热）

| 基准套件 | 攻击拒绝率 | 良性接纳率 | 攻击样本 | 良性样本 |
|---------|-----------|-----------|---------|---------|
| **OWASP LLM Top 10** | 93.9% | 29.6% | 49 | 27 |
| **raucle-bench 兼容** | 85.0% | 70.0% | 40 | 20 |

### 反馈回灌验证（活性防护闭环）

| 阶段 | OWASP攻击拒绝率 |
|------|-----------------|
| 初始测试 | 93.9%（3条漏检） |
| 回灌后 | **100%**（3条全部修复） |

### 硬件配置推荐

| 部署规模 | 硬件规格 | STANDARD层级预期性能 | 内存占用 |
|---------|---------|----------------------|----------|
| 个人开发/测试 | 1核2G | 延迟~10ms，QPS~50 | <300MB |
| 中小型API | 2核4G | 延迟~7ms，QPS~100 | <500MB |
| 生产环境 | 4核8G | 延迟~5ms，QPS~200 | <1GB |
| 高并发 | 8核16G+ | 延迟~4ms，QPS~500+ | <2GB |

详细报告见 [docs/benchmarks.md](docs/benchmarks.md)。

## 双许可证说明

本仓库采用**分层许可证**保护核心算法：

### 核心算法 — 道体研究许可证 v1.0

以下文件受 [LICENSE](LICENSE)（道体研究许可证 v1.0）约束：

- `src/daoti_xuandun/reject_gate.py` — 拒绝门核心算法
- `src/daoti_xuandun/preprocessors.py` — 预处理管道
- `src/daoti_xuandun/config.py` — 配置对象（含动态活性参数）
- `src/daoti_xuandun/xuandun.py` — 主引擎入口
- `src/daoti_xuandun/luoshu_mapper.py` — 洛书符号映射器
- `src/daoti_xuandun/secure_strings.py` — 敏感参数保护
- `src/daoti_xuandun/timing_checker.py` — 时序一致性校验
- `src/daoti_xuandun/dynamic_shell.py` — 动态阴阳壳
- `src/daoti_xuandun/ancient_mapper.py` — 自组织符号映射
- `src/daoti_xuandun/atlas_mapping.py` — 图谱映射
- `desktop/xuandun-desktop/engine_flask.py` — 引擎 Flask 服务
- `desktop/xuandun-desktop/anti_debug.py` — 反逆向检测
- `desktop/xuandun-desktop/build_engine.py` — Nuitka 编译脚本

**核心限制**：
- ✅ 允许：使用、复制、分发仓库资产
- ✅ 允许：用于 LLM 输入检测（包括商业应用）
- ❌ 禁止：逆向工程、反编译、重建架构源码
- ❌ 禁止：再分发核心算法二进制（xuandun-engine）作为独立产品
- ⚠️ 商业用途需另行授权（详见 LICENSE Section 2.2）

### 外围代码 — Apache 2.0

Rust 桌面端、TypeScript 前端、配置文件、文档、测试受 [LICENSE_CODE](LICENSE_CODE)（Apache License 2.0）约束。

详见 [NOTICE](NOTICE)。

## 从源码构建

### 环境要求

- **Python** 3.11+
- **Rust** 1.75+（stable）
- **Node.js** 20+
- **Nuitka** 2.x（`pip install nuitka`）

### 构建步骤

```bash
# 1. 克隆仓库
git clone https://github.com/zhibaiYingChuan/xuandun.git
cd xuandun

# 2. 安装 Python 依赖
pip install -e .

# 3. 编译 Nuitka 引擎二进制（生成 src-tauri/binaries/xuandun-engine-*）
cd desktop/xuandun-desktop
python build_engine.py

# 4. 安装前端依赖
npm install

# 5. 构建 Tauri 桌面应用
npm run tauri build
```

构建产物位于 `desktop/xuandun-desktop/src-tauri/target/release/bundle/`。

### 三端 CI/CD

本项目使用 GitHub Actions 自动构建三端安装包。推送 `v*` 标签即触发：

```bash
git tag v1.0.0
git push origin v1.0.0
```

详见 [.github/workflows/release.yml](.github/workflows/release.yml)。

## 命令行工具

```bash
# 交互式配置向导
python -m daoti_xuandun.setup

# 域档案管理
python -m daoti_xuandun.manage init --domain mydata.txt --output profile.json
python -m daoti_xuandun.manage export --output profile.json --raw
python -m daoti_xuandun.manage import --input profile.json

# 性能基准测试
python -m daoti_xuandun.benchmark.performance_benchmark --level STANDARD --requests 100

# 行业基准测试
python -m industry_benchmarks.run --suite owasp_llm_top10 --mode balanced --warmup-en
```

## 防御层级（高级）

```python
from daoti_xuandun import XuanDunConfig, DefenseLevel

# BASIC — 内部低风险场景（~48%攻击拒绝率，最快）
config = XuanDunConfig.for_level(DefenseLevel.BASIC)

# STANDARD — 生产环境推荐（≥95%攻击拒绝率，延迟~5ms）
config = XuanDunConfig.for_level(DefenseLevel.STANDARD)

# STRICT — 高安全场景（≥98%攻击拒绝率，延迟~7ms）
config = XuanDunConfig.for_level(DefenseLevel.STRICT)

# PARANOID — 极端安全场景（延迟~12ms）
config = XuanDunConfig.for_level(DefenseLevel.PARANOID)
```

## FastAPI 集成

```python
from fastapi import FastAPI
from daoti_xuandun.integrations.fastapi import XuanDunGuard

app = FastAPI()
guard = XuanDunGuard(level="STANDARD")

@app.post("/chat")
@guard.protect
async def chat(message: str):
    return {"response": "处理安全的输入"}
```

## 贡献

欢迎提交 Issue 和 PR！

**注意**：
- 外围代码（Rust/TS/文档/配置）修改：直接提交 PR，遵循 Apache 2.0
- 核心算法修改：需签署 CLA（Contributor License Agreement），请联系作者
- 请勿在 PR 中暴露核心算法的设计意图注释或原始类名

## 引用

如需在学术论文中引用本项目：

```bibtex
@software{xuandun2026,
  title={道体·玄盾: 活性防护 LLM 防火墙},
  author={独立研究者，知白},
  year={2026},
  url={https://github.com/zhibaiYingChuan/xuandun}
}
```

## 联系方式

- **作者**：独立研究者，知白
- **Email**：spring60@vip.qq.com
- **Website**：sfang.cc
- **Repository**：https://github.com/zhibaiYingChuan/xuandun

## 常见问题

**Q: 我需要自己准备"预热样本"吗？**

不需要。默认 `auto_warmup=True`，系统会使用内置安全样本自动预热。您也可以后续提供业务样本提升适应度。

**Q: 如何降低误报？**
- 使用 `mode="low_false_positive"` 或 `balanced`
- 向 `warmup_safe` 中添加更多您的合法输入样本
- 调用 `shield.explain_debug(result)` 理解每条误判的具体原因

**Q: 系统能防御所有攻击吗？**

不能。基准测试显示对**测试集中的已知攻击模式**拒绝率达到100%，但对从未见过的、与正常文本无统计差异的攻击可能漏过（此时系统会将其纳入混沌期孵化，多次出现后会自动学习并阻止）。**安全是过程，不是终点**。

**Q: 核心算法为什么不开源？**

核心算法受道体研究许可证 v1.0 保护，作为商业秘密受到法律保护。开源仓库包含 Nuitka 编译的二进制（脱敏版本），使用机器码常量且不含设计意图注释。如需学术研究访问架构源码，请提交学术使用申请（详见 LICENSE Section 2.2）。

## 许可证

- 核心算法：[道体研究许可证 v1.0](LICENSE)
- 外围代码：[Apache License 2.0](LICENSE_CODE)
- 声明：[NOTICE](NOTICE)
