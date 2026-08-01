#!/bin/bash
# 道体·玄盾 Web Demo 一键部署脚本（Linux 服务器）
# 使用方式：在项目根目录执行 bash web-demo/deploy.sh
set -e

echo "=========================================="
echo "  道体·玄盾 Web Demo 部署脚本"
echo "=========================================="

# 检查 Docker
if ! command -v docker &> /dev/null; then
    echo "错误：Docker 未安装，请先安装 Docker"
    exit 1
fi

if ! docker compose version &> /dev/null; then
    echo "错误：Docker Compose 未安装"
    exit 1
fi

# 步骤1：构建前端
echo ""
echo "[1/4] 构建前端..."
cd web-demo/frontend
npm install --silent
npm run build
cd ../..

# 步骤2：构建 Docker 镜像
echo ""
echo "[2/4] 构建 Docker 镜像（包含核心算法源码）..."
docker compose -f web-demo/docker-compose.yml build

# 步骤3：启动服务
echo ""
echo "[3/4] 启动服务..."
docker compose -f web-demo/docker-compose.yml up -d

# 步骤4：健康检查
echo ""
echo "[4/4] 等待后端启动..."
for i in $(seq 1 30); do
    if curl -sf http://localhost:8000/api/health > /dev/null 2>&1; then
        echo "后端健康检查通过"
        break
    fi
    sleep 2
    if [ $i -eq 30 ]; then
        echo "警告：后端健康检查超时，请检查日志："
        echo "  docker compose -f web-demo/docker-compose.yml logs backend"
    fi
done

echo ""
echo "=========================================="
echo "  部署完成！"
echo "=========================================="
echo "  前端：http://localhost:5173"
echo "  后端：http://localhost:8000"
echo "  健康检查：http://localhost:8000/api/health"
echo ""
echo "  查看日志：docker compose -f web-demo/docker-compose.yml logs -f"
echo "  停止服务：docker compose -f web-demo/docker-compose.yml down"
echo "=========================================="
