FROM python:3.12-alpine@sha256:6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app
ARG PAMOLIVE_RUNTIME_UID=10001
ARG PAMOLIVE_RUNTIME_GID=10001
RUN addgroup -S -g "${PAMOLIVE_RUNTIME_GID}" pamolive \
    && adduser -S -D -H -u "${PAMOLIVE_RUNTIME_UID}" -G pamolive pamolive
COPY requirements.lock ./
RUN pip install --require-hashes -r requirements.lock
COPY app.py backends.py rate_limit.py init_redis_tls.py init_keyring_tls.py ./

EXPOSE 8000
USER pamolive
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
