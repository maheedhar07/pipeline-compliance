FROM python:3.11-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app

# dependencies first (better layer caching)
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install ".[postgres]"

COPY config ./config
RUN useradd --create-home --uid 10001 pch && mkdir -p /app/data && chown -R pch:pch /app
USER pch

ENV DATABASE_URL=sqlite:////app/data/pch.db \
    DATA_DIR=/app/data
VOLUME ["/app/data"]
EXPOSE 8000

# The dashboard has NO authentication in v1. Do not publish this port beyond localhost
# unless it sits behind Entra ID (see README: Azure App Service Easy Auth).
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health', timeout=3).status == 200 else 1)"
CMD ["pch", "serve", "--host", "0.0.0.0", "--port", "8000"]
