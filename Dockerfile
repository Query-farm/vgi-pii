# Copyright 2026 Query Farm LLC - https://query.farm
#
# Single image serving BOTH transports of the vgi-pii worker:
#   docker run ... IMG            -> HTTP server on $PORT (default 8000; /health, VGI RPC)
#   docker run -i ... IMG stdio   -> stdio worker DuckDB spawns on-host
# See docker-entrypoint.sh. Keyless; PII detection/redaction runs in-process via
# Microsoft Presidio + a pinned en_core_web_sm spaCy model. No persistent state volume.
# syntax=docker/dockerfile:1
FROM python:3.13-slim

ARG VERSION=0.0.0
ARG GIT_COMMIT=unknown
ARG SOURCE_URL=https://github.com/Query-farm/vgi-pii

LABEL org.opencontainers.image.title="vgi-pii" \
      org.opencontainers.image.description="Detect + redact PII in text (Microsoft Presidio) as a VGI worker for DuckDB/SQL (stdio + HTTP)" \
      org.opencontainers.image.source="${SOURCE_URL}" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${GIT_COMMIT}" \
      org.opencontainers.image.licenses="MIT" \
      farm.query.vgi.transports='["http","stdio"]'

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PORT=8000

WORKDIR /app

# curl backs the HEALTHCHECK and the CI /health smoke.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# Install the worker + HTTP-serving extra from the source tree (version read by hatchling).
COPY pyproject.toml README.md LICENSE ./
COPY vgi_pii ./vgi_pii
RUN pip install '.[serve]'

# Presidio defaults to the ~400 MB en_core_web_lg model and would try to DOWNLOAD it at
# runtime; the worker instead pins the small en_core_web_sm (~12 MB, MIT). It is not a PyPI
# package, so install it from the spaCy-models release wheel by direct URL (matches the
# pyproject `[tool.uv.sources]` pin + the pii_worker.py PEP 723 header).
RUN pip install \
    "en_core_web_sm @ https://github.com/explosion/spacy-models/releases/download/en_core_web_sm-3.8.0/en_core_web_sm-3.8.0-py3-none-any.whl"

# Warm the Presidio analyzer + spaCy model once at build time so the first query in a
# running container is fast (best-effort; never fails the build).
RUN python -c "from vgi_pii import engine; engine.warm_up()" || true

COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=8s \
    CMD curl -fsS "http://localhost:${PORT}/health" || exit 1

ENTRYPOINT ["docker-entrypoint.sh"]
