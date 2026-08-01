# 道体·玄盾 Web Demo

> 活性防护 LLM 防火墙在线演示 — 复赛评审零门槛体验

## 快速开始

### 方式1：Docker Compose 一键部署（推荐）

```bash
# 构建前端
cd frontend && npm install && npm run build && cd ..

# 启动服务
docker-compose up -d

# 访问
# 前端: http://localhost:5173
# 后端 API: http://localhost:8000
```

### 方式2：本地开发

```bash
# 终端1：启动后端
cd backend
pip install -r requirements.txt
python app.py

# 终端2：启动前端
cd frontend
npm install
npm run dev
# 访问 http://localhost:5173
```

### 方式3：云端部署

- **前端**：部署到 [netlify](https://netlify.com)，已配置 `netlify.toml`
- **后端**：部署到 [Railway](https://railway.app) / [Render](https://render.com) / [Fly.io](https://fly.io)

## 功能模块

| 页面 | 路径 | 功能 |
|------|------|------|
| 首页 | `/` | 产品介绍 + 核心数据 + 双层架构说明 |
| 安全检测 | `/detect` | 单条文本检测 + 快速测试样本 |
| 阴阳门演示 | `/yinyang` | 一键演示双层架构完整工作流程 |
| 模拟测试 | `/simulation` | 批量攻击+安全样本对比测试 |
| 学习状态 | `/learning` | 在线学习进度 + 原型库规模 |

## 核心算法保护

1. 后端通过 `daoti-xuandun` SDK 调用核心算法，不暴露源码
2. API 只返回检测结果和统计数据，不返回算法内部状态
3. 生产环境使用 Nuitka 编译核心算法为二进制
4. 前端无法访问 `reject_gate.py` / `luoshu_mapper.py` 等核心文件

## 技术栈

- **后端**：FastAPI + uvicorn + daoti-xuandun SDK
- **前端**：React 18 + Vite 5 + recharts + lucide-react
- **部署**：Docker / netlify / Railway

## 演示亮点

1. **一键演示**：30 秒看懂双层阴阳架构工作原理
2. **实时统计**：阳门/阴门拦截数据实时更新
3. **攻击样本库**：覆盖 OWASP LLM Top 10 六大类攻击
4. **学习可视化**：在线学习进度 + 原型库规模展示
