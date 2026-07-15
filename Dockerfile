FROM python:3.12-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
RUN groupadd --system cbpam && useradd --system --gid cbpam --create-home cbpam
WORKDIR /app
COPY pyproject.toml README.md ./
COPY cbpam ./cbpam
COPY config ./config
COPY manage.py ./
RUN pip install --upgrade pip && pip install .
COPY templates ./templates
COPY static ./static
RUN python manage.py collectstatic --noinput --settings=config.settings.local
USER cbpam
EXPOSE 8000
CMD ["daphne", "-b", "0.0.0.0", "-p", "8000", "config.asgi:application"]

