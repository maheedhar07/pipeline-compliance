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
# requirements-azure.lock (adds azuresql, azure-keyvault, azure-blob, azure-monitor; see README "Dependency lockfile").
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

# Bind address, port and auth come from settings (HOST, PORT / WEBSITES_PORT, AUTH_MODE, ...). Nothing is hard-coded here:
# the default HOST=127.0.0.1 is unreachable from outside the container on purpose, and `pch serve` refuses to start on a
# non-loopback address unless authentication is configured (see README "Security").
#   * App Service: set HOST=0.0.0.0, APP_ENV=prod, AUTH_MODE=easyauth, AUTH_ALLOWED_ROLES, ALLOWED_HOSTS, WEBSITES_PORT (docs/DEPLOY_AZURE.md)
#   * local compose: APP_ENV=dev, AUTH_MODE=none, AUTH_NONE_ALLOW_CONTAINER_BIND=true, port published to 127.0.0.1 only
# The probe may use a loopback Host header: the trusted-host check allows exactly the health paths for that.
# /health/live = process only (a DB outage must not restart the container); the platform probe uses /health/ready.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s CMD python -c "import os,sys,urllib.request as u; p=os.environ.get('PORT') or os.environ.get('WEBSITES_PORT') or '8000'; sys.exit(0 if u.urlopen('http://127.0.0.1:'+p+'/health/live', timeout=3).status == 200 else 1)"
CMD ["pch", "serve"]
