# 道体·玄盾 Web Demo 后端 Dockerfile
# 核心算法保护策略：源码打包进镜像，不发布到 PyPI，不暴露源码仓库
FROM python:3.11-slim

LABEL maintainer="Daoti XuanDun Team"
LABEL description="Daoti XuanDun Web Demo Backend"

WORKDIR /app

# 安装系统依赖（numpy 编译需要 gcc）
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ curl && \
    rm -rf /var/lib/apt/lists/*

# 先 COPY pyproject.toml 和 src/（核心算法源码，打包进镜像不外露）
COPY pyproject.toml /app/
COPY src/ /app/src/

# 安装核心算法（从源码安装，不依赖 PyPI）
RUN pip install --no-cache-dir .

# 安装后端 Web 依赖（过滤掉 daoti-xuandun 行，已从源码安装）
COPY web-demo/backend/requirements.txt /tmp/requirements.txt
RUN grep -v 'daoti-xuandun' /tmp/requirements.txt > /tmp/req_filtered.txt && \
    pip install --no-cache-dir -r /tmp/req_filtered.txt

# COPY 后端应用代码
COPY web-demo/backend/app.py /app/

ENV PORT=8000
ENV CORS_ORIGINS="*"
ENV PYTHONUNBUFFERED=1

EXPOSE 8000

# 健康检查
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD curl -f http://localhost:8000/api/health || exit 1

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
