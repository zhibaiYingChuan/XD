# 贡献指南（Contributing Guide）

感谢您考虑为道体·玄盾贡献！本文档指导您完成贡献流程。

## 贡献方式

- 提交 Issue 报告 Bug 或建议功能
- 提交 Pull Request 修复 Bug 或实现功能
- 完善文档
- 分享使用经验

## 开发环境

### 前置要求

- Python 3.11+
- Rust 1.75+（stable）
- Node.js 20+
- Nuitka 4.x（`pip install nuitka`）

### 本地启动

```bash
git clone https://github.com/zhibaiYingChuan/XD.git
cd XD

# Python 依赖
pip install -e ".[engine]"

# 前端依赖
cd desktop/xuandun-desktop
npm install

# 开发模式
npm run tauri dev
```

## 许可证分类

### 外围代码（Apache 2.0）

Rust 桌面端、TypeScript 前端、配置文件、文档、测试受 [LICENSE_CODE](LICENSE_CODE)（Apache 2.0）约束。直接提交 PR 即可。

### 核心算法（道体研究许可证 v1.0）

以下文件受 [LICENSE](LICENSE)（道体研究许可证 v1.0）约束，修改需签署 CLA：

- `src/daoti_xuandun/reject_gate.py`
- `src/daoti_xuandun/luoshu_mapper.py`
- `src/daoti_xuandun/dynamic_shell.py`
- `src/daoti_xuandun/preprocessors.py`
- `src/daoti_xuandun/config.py`
- `src/daoti_xuandun/xuandun.py`
- `src/daoti_xuandun/secure_strings.py`
- `src/daoti_xuandun/timing_checker.py`
- `src/daoti_xuandun/ancient_mapper.py`
- `src/daoti_xuandun/atlas_mapping.py`
- `desktop/xuandun-desktop/engine_flask.py`
- `desktop/xuandun-desktop/build_engine.py`

**注意**：请勿在 PR 中暴露核心算法的设计意图注释或原始类名。修改核心算法请先联系 spring60@vip.qq.com 签署 CLA。

## 提交规范

使用 [Conventional Commits](https://www.conventionalcommits.org/) 格式：

```
<type>: <description>

[optional body]
```

### Type 列表

- `feat`: 新功能
- `fix`: Bug 修复
- `docs`: 文档
- `chore`: 构建/工具
- `ci`: CI/CD
- `refactor`: 重构
- `test`: 测试

### 示例

```
feat: v1.5.0 企业评估工具包 逃生通道/灰度部署/日志重放/配置回滚/行业样本/快速验证
fix: v1.2.2 根因修复 — flask/waitress 声明为 engine optional deps
docs: 更正仓库地址为 zhibaiYingChuan/XD 并清理文档夸大内容
```

## PR 流程

1. Fork 仓库并创建分支（`feat/xxx` 或 `fix/xxx`）
2. 确保本地构建通过（`npm run tauri build`）
3. 确保版本号一致（`python sync_version.py --check`）
4. 提交 PR，填写 PR 模板
5. 等待 CODEOWNERS 审查
6. 通过后合并

## 安全漏洞

请勿在 PR 中修复安全漏洞。参考 [SECURITY.md](SECURITY.md) 报告安全漏洞。

## 行为准则

- 尊重所有贡献者
- 接受建设性批评
- 关注项目目标而非个人
