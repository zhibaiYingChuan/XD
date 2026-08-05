FROM python:3.11-slim

LABEL maintainer="Daoti XuanDun Team"
LABEL description="Daoti XuanDun - Active Defense Security Gateway for LLM Runtime"
LABEL version="1.3.2"

WORKDIR /app

# 复制 Python 核心包与桌面端引擎入口
# 注意：industry_benchmarks/ 目录已移除（项目中不存在该目录）
COPY pyproject.toml .
COPY README.md .
COPY src/ src/
COPY desktop/xuandun-desktop/engine_flask.py .
COPY desktop/xuandun-desktop/simulation.py .

# 安装引擎依赖（Flask + waitress）
RUN pip install --no-cache-dir -e ".[engine]"

ENV XUANDUN_MODE=balanced
# 生产环境强制使用 waitress，禁用 Flask 开发服务器 fallback
ENV XUANDUN_REQUIRE_WAITRESS=1

EXPOSE 18765
# 启动 Flask 引擎服务（waitress 生产级 WSGI）
CMD ["python", "engine_flask.py", "--host", "0.0.0.0", "--port", "18765", "--mode", "balanced"]
