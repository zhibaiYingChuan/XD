# 道体·玄盾 Web Demo

> 活性防护 LLM 防火墙在线演示 — 复赛评审零门槛体验

## 复赛线上部署指南（Netlify + Render）

### 前置准备
1. GitHub 仓库已推送（包含 web-demo/ 和 render.yaml）
2. 注册 [Netlify](https://app.netlify.com/) 账号（支持 GitHub 登录）
3. 注册 [Render](https://dashboard.render.com/) 账号（支持 GitHub 登录）

### 步骤1：部署后端到 Render

1. 登录 Render Dashboard → 点击 **New +** → 选择 **Blueprint**
2. 选择 GitHub 仓库 `zhibaiYingChuan/XD`
3. Render 会自动识别 `render.yaml` 配置文件
4. 确认配置：
   - Service Name: `xuandun-demo-api`
   - Environment: Docker
   - Dockerfile Path: `./Dockerfile`
   - Docker Context: `.`
   - Plan: Free
5. 点击 **Apply** 开始部署
6. 等待部署完成（首次约 5-10 分钟，包含 pip install + Nuitka 编译）
7. 记录后端地址，格式为 `https://xuandun-demo-api.onrender.com`
8. 验证：访问 `https://xuandun-demo-api.onrender.com/api/health`，应返回 `{"status":"ok"}`

### 步骤2：部署前端到 Netlify

1. 登录 Netlify Dashboard → 点击 **Add new site** → **Import an existing project**
2. 选择 GitHub 仓库 `zhibaiYingChuan/XD`
3. 配置构建设置（Netlify 会自动读取 `web-demo/netlify.toml`）：
   - Base directory: `web-demo/frontend`
   - Build command: `npm install && npm run build`
   - Publish directory: `web-demo/frontend/dist`
4. 配置环境变量（Site settings → Environment variables）：
   - `VITE_API_BASE` = `https://xuandun-demo-api.onrender.com`（替换为步骤1的实际地址）
5. 点击 **Deploy site** 开始部署
6. 等待部署完成（约 2-3 分钟）
7. 获取前端地址，格式为 `https://xuandun-demo.netlify.app`

### 步骤3：更新 API 代理地址

1. 在本地编辑 `web-demo/netlify.toml`
2. 将 `to = "https://xuandun-demo-api.onrender.com/api/:splat"` 替换为步骤1的实际后端地址
3. git commit 并 push
4. Netlify 会自动重新部署

### 步骤4：验证部署

1. 访问前端地址（如 `https://xuandun-demo.netlify.app`）
2. 验证首页正常加载，太极动画运行
3. 验证"阴阳门演示"页面，点击"一键演示双层架构"
4. 验证"安全检测"页面，输入测试文本
5. 验证"模拟测试"页面，批量攻击测试
6. 验证"学习状态"页面，查看学习进度

### 常见问题

**Q: Render 后端启动失败？**
- 检查 Dockerfile 路径是否正确（`./Dockerfile`，context 为 `.`）
- 查看 Render 部署日志，确认 `pip install .` 成功
- 确认 `src/daoti_xuandun/` 目录已推送到 GitHub

**Q: Netlify 前端 API 调用失败（CORS 错误）？**
- 确认 Render 后端已启动且 `/api/health` 返回 200
- 检查 `netlify.toml` 中的 API 代理地址是否正确
- Render 免费版有冷启动延迟（约 30 秒），首次请求可能超时

**Q: 部署后页面空白？**
- 检查浏览器控制台是否有 JS 错误
- 确认 `VITE_API_BASE` 环境变量已正确设置
- 尝试清除浏览器缓存后重新访问

## 本地开发

### 方式1：Docker Compose 一键部署（推荐）

```bash
# 构建前端
cd web-demo/frontend && npm install && npm run build && cd ../..

# 启动服务
docker compose -f web-demo/docker-compose.yml up -d

# 访问
# 前端: http://localhost:5173
# 后端 API: http://localhost:8000
```

### 方式2：本地开发模式

```bash
# 终端1：启动后端
cd web-demo/backend
pip install -r requirements.txt
# 先安装核心算法（从项目根目录）
pip install -e ..
python app.py

# 终端2：启动前端
cd web-demo/frontend
npm install
npm run dev
# 访问 http://localhost:5173
```

## 功能模块

| 页面 | 路径 | 功能 |
|------|------|------|
| 首页 | `/` | 产品介绍 + 核心数据 + 双层架构说明 + 技术亮点 |
| 安全检测 | `/detect` | 单条文本检测 + 信任等级可视化 + 历史记录 |
| 阴阳门演示 | `/yinyang` | 一键演示双层架构完整工作流程 + A/B对比 |
| 模拟测试 | `/simulation` | 批量攻击测试 + 图表分析 + 结果详情 |
| 学习状态 | `/learning` | 环形进度条 + 原型库统计 + 学习时间线 |

## 核心算法保护

1. 后端通过 `daoti-xuandun` SDK 调用核心算法，不暴露源码
2. API 只返回检测结果和统计数据，不返回算法内部状态
3. 生产环境使用 Nuitka 编译核心算法为二进制
4. 前端无法访问 `reject_gate.py` / `luoshu_mapper.py` 等核心文件
5. Docker 镜像内包含源码，但不挂载源码卷

## 技术栈

- **后端**：FastAPI + uvicorn + daoti-xuandun SDK
- **前端**：React 18 + Vite 5 + recharts + lucide-react
- **部署**：Docker / Netlify / Render

## 演示亮点

1. **一键演示**：30 秒看懂双层阴阳架构工作原理
2. **实时统计**：阳门/阴门拦截数据实时更新
3. **攻击样本库**：覆盖 OWASP LLM Top 10 六大类攻击
4. **学习可视化**：在线学习进度 + 原型库规模展示
5. **A/B对比**：单层 vs 双层防护效果差异可视化
