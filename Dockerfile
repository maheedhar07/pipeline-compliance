# Base image is pinned by digest. To bump: look up the new digest of python:3.11-slim
# (multi-arch index), e.g.
#   docker buildx imagetools inspect python:3.11-slim   (or Docker Hub registry API HEAD on the manifest)
# and replace the sha256 below in BOTH stages. Dependabot (docker ecosystem) also proposes bumps.
# ---- builder: install locked, hash-verified deps into a venv, then the project itself ----
FROM python:3.11-slim@sha256:bab1b7ef4b450c81002278d035eff85ebe394ae94df904f7a3ba14f7e16e487b AS builder
ENV PYTHONDONTWRITEBYTECODE=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /build
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# PCH_LOCKFILE selects the hash-locked dependency set: requirements.lock (default: core + postgres) or
# requirements-azure.lock (adds azuresql, azure-keyvault, azure-blob; see README "Dependency lockfile").
# Regenerate with: pip-compile --generate-hashes --extra postgres -o requirements.lock pyproject.toml
ARG PCH_LOCKFILE=requirements.lock
COPY ${PCH_LOCKFILE} ./requirements.lock
RUN pip install --require-hashes --no-deps -r requirements.lock

COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-deps .

# ---- final: venv only, no build tooling beyond what the base image ships ----
FROM python:3.11-slim@sha256:bab1b7ef4b450c81002278d035eff85ebe394ae94df904f7a3ba14f7e16e487b
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PATH="/opt/venv/bin:$PATH"
WORKDIR /app
COPY --from=builder /opt/venv /opt/venv

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
