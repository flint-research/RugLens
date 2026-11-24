# syntax=docker/dockerfile:1.7
# Multi-stage image: Python wheel environment + statically copied Foundry tools.
ARG FOUNDRY_IMAGE=ghcr.io/foundry-rs/foundry:stable

FROM python:3.12-slim-bookworm AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /build
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN python -m venv /opt/venv \
    && /opt/venv/bin/python -m pip install --upgrade pip setuptools wheel \
    && /opt/venv/bin/python -m pip install .

FROM ${FOUNDRY_IMAGE} AS foundry
RUN cp "$(command -v anvil)" /tmp/anvil \
    && cp "$(command -v cast)" /tmp/cast \
    && /tmp/anvil --version

FROM python:3.12-slim-bookworm AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH=/opt/venv/bin:$PATH \
    RUGLENS_DATA_DIR=/data \
    RUGLENS_API_HOST=0.0.0.0 \
    RUGLENS_API_PORT=8000 \
    RUGLENS_SIMULATION_CONCURRENCY=2

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 ruglens \
    && useradd --uid 10001 --gid ruglens --create-home --shell /usr/sbin/nologin ruglens \
    && mkdir -p /data /home/ruglens/.ruglens \
    && chown -R ruglens:ruglens /data /home/ruglens

COPY --from=builder /opt/venv /opt/venv
COPY --from=foundry /tmp/anvil /usr/local/bin/anvil
COPY --from=foundry /tmp/cast /usr/local/bin/cast

RUN chmod 0755 /usr/local/bin/anvil /usr/local/bin/cast \
    && /usr/local/bin/anvil --version

USER ruglens:ruglens
VOLUME ["/data"]
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=25s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/v1/health', timeout=3).read()"]

ENTRYPOINT ["ruglens"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8000"]
