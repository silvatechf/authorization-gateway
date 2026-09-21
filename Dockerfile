FROM python:3.11-slim AS base

RUN groupadd --gid 1000 gateway \
    && useradd --uid 1000 --gid gateway --shell /bin/bash --create-home gateway

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY scripts ./scripts

RUN mkdir -p /app/.devkeys && chown -R gateway:gateway /app

USER gateway

ENV JWKS_MODE=dev \
    DEV_KEYS_DIR=/app/.devkeys \
    PYTHONUNBUFFERED=1

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/healthz')" || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
