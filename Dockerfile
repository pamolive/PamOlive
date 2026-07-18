FROM python:3.14-alpine@sha256:26730869004e2b9c4b9ad09cab8625e81d256d1ce97e72df5520e806b1709f92 AS runtime
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
