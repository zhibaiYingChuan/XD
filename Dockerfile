# 玄盾企业级安全网关 Docker 镜像
# 支持两种模式: engine (Flask 桌面端引擎) / gateway (FastAPI 网关)
#
# 构建: docker build -t xuandun-gateway:1.3.3 .
# 运行: docker run -p 18766:18766 xuandun-gateway:1.3.3
# Compose: docker compose up -d

# ── 构建阶段 ──
FROM python:3.11-slim AS builder

WORKDIR /app

# 安装构建依赖
RUN pip install --no-cache-dir -U pip setuptools wheel

# 分层复制：先复制依赖配置，利用 Docker 缓存
COPY pyproject.toml .
COPY README.md .

# 安装 gateway 依赖（FastAPI + uvicorn + httpx + pydantic + pyyaml）
RUN pip install --no-cache-dir \
    numpy>=1.24 \
    fastapi>=0.110 \
    "uvicorn[standard]>=0.27" \
    "httpx[http2]>=0.27" \
    pydantic>=2.5 \
    pyyaml>=6.0 \
    "PyJWT>=2.8"

# ── 运行阶段 ──
FROM python:3.11-slim AS runtime

LABEL maintainer="DaoTi XuanDun Team"
LABEL description="XuanDun AI Security Gateway - Enterprise-grade LLM Runtime Protection"
LABEL version="1.3.3"
LABEL org.opencontainers.image.source="https://github.com/zhibaiYingChuan/XD"
LABEL org.opencontainers.image.title="玄盾 AI安全网关"

WORKDIR /app

# 从 builder 复制已安装的 site-packages（避免 pip install 重复解析）
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# 复制源码
COPY src/ src/
COPY gateway/ gateway/

# 复制默认配置文件
COPY gateway/config.yaml /etc/xuandun/config.yaml

# 健康检查（/health 端点，端口与 CMD 一致）
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; r=urllib.request.urlopen('http://localhost:18766/health'); assert r.status==200" || exit 1

# 环境变量默认值
ENV XUANDUN_MODE=protecting
ENV XUANDUN_LOG_LEVEL=info
ENV XUANDUN_CONFIG_PATH=/etc/xuandun/config.yaml
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

EXPOSE 18766

# 以网关模式启动
CMD ["python", "-m", "uvicorn", "gateway.app:app", "--host", "0.0.0.0", "--port", "18766", "--log-level", "info"]
