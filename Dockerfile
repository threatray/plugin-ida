# syntax=docker/dockerfile:1
# check=error=true
ARG VERSION=3.14
FROM python:$VERSION-bookworm AS builder
LABEL maintainer="Threatray <operations@threatray.com>"

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends libgl1 && \
    rm -rf /var/lib/apt/lists/*

ENV VIRTUAL_ENV=/app/venv
ENV PATH="$VIRTUAL_ENV/bin:$PATH"
ENV UV_PROJECT_ENVIRONMENT=$VIRTUAL_ENV
ENV UV_CACHE_DIR=/tmp/.uv_cache
ENV UV_COMPILE_BYTECODE=1
ENV UV_LINK_MODE=copy

RUN mkdir /app
WORKDIR /app
COPY --from=ghcr.io/astral-sh/uv:0.13.8 /uv /uvx /bin/

FROM builder AS lock

ENV HOME=/app/threatray-ida
WORKDIR $HOME
COPY pyproject.toml $HOME
RUN uv lock --upgrade

FROM builder AS base

ENV HOME=/app/threatray-ida
WORKDIR $HOME
COPY pyproject.toml uv.lock $HOME/
RUN --mount=type=cache,target=/tmp/.uv_cache \
    uv sync --locked

FROM python:$VERSION-slim-bookworm AS slim

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends libgl1 && \
    rm -rf /var/lib/apt/lists/*

FROM slim AS external

COPY --from=base /app /app
COPY threatray_ida /app/threatray-ida/threatray_ida
COPY threatray_plugin.py /app/threatray-ida/threatray_plugin.py
RUN rm -rf /app/threatray-ida/threatray_ida/internal

FROM slim

COPY --from=base /app /app
COPY threatray_ida /app/threatray-ida/threatray_ida
COPY threatray_plugin.py /app/threatray-ida/threatray_plugin.py
