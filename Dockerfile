FROM python:3.12-alpine@sha256:6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
ARG PAMOLIVE_RUNTIME_UID=10001
ARG PAMOLIVE_RUNTIME_GID=10001
RUN addgroup -S -g "${PAMOLIVE_RUNTIME_GID}" pamolive \
    && adduser -S -D -H -u "${PAMOLIVE_RUNTIME_UID}" -G pamolive pamolive
WORKDIR /app
COPY requirements.lock ./
RUN pip install --require-hashes -r requirements.lock
COPY pamolive ./pamolive
COPY config ./config
COPY manage.py ./
COPY templates ./templates
COPY static ./static
RUN python manage.py collectstatic --noinput --settings=config.settings.base
USER pamolive
EXPOSE 8000
CMD ["daphne", "-b", "0.0.0.0", "-p", "8000", "config.asgi:application"]
