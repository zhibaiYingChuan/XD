FROM python:3.11-slim

LABEL maintainer="Daoti XuanDun Team"
LABEL description="Daoti XuanDun - Active Defense Security Gateway for LLM Runtime"
LABEL version="1.0.0"

WORKDIR /app

COPY pyproject.toml .
COPY src/ src/
COPY run_benchmark.py .
COPY industry_benchmarks/ industry_benchmarks/
COPY scripts/ scripts/

RUN pip install --no-cache-dir -e .

ENV XUANDUN_MODE=balanced

CMD ["python", "-m", "industry_benchmarks.run", "--suite", "all", "--mode", "balanced", "--warmup-en"]
