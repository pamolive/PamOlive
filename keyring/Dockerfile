FROM ghcr.io/astral-sh/uv:latest@sha256:ecd4de2f060c64bea0ff8ecb182ddf46ba3fcccdc8a60cfdbaf20d1a047d7437 AS uv
FROM python:3.12-alpine@sha256:6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 UV_LINK_MODE=copy

WORKDIR /app
ARG PAMOLIVE_RUNTIME_UID=10001
ARG PAMOLIVE_RUNTIME_GID=10001
RUN addgroup -S -g "${PAMOLIVE_RUNTIME_GID}" pamolive \
    && adduser -S -D -H -u "${PAMOLIVE_RUNTIME_UID}" -G pamolive pamolive

COPY --from=uv /uv /bin/uv
COPY pyproject.toml uv.lock ./
COPY keyring/pyproject.toml ./keyring/
RUN uv sync --frozen --package pam-olive-keyring --no-dev
ENV PATH="/app/.venv/bin:$PATH"

COPY keyring/app.py keyring/backends.py keyring/rate_limit.py \
     keyring/init_redis_tls.py keyring/init_keyring_tls.py ./

EXPOSE 8000
USER pamolive
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
