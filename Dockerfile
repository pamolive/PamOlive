FROM python:3.12-alpine@sha256:6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
RUN addgroup -S pamolive && adduser -S -G pamolive -h /home/pamolive pamolive
WORKDIR /app
COPY pyproject.toml README.md ./
COPY pamolive ./pamolive
COPY config ./config
COPY manage.py ./
RUN pip install --upgrade pip && pip install .
COPY templates ./templates
COPY static ./static
RUN python manage.py collectstatic --noinput --settings=config.settings.base
USER pamolive
EXPOSE 8000
CMD ["daphne", "-b", "0.0.0.0", "-p", "8000", "config.asgi:application"]
