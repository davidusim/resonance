FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    RESONANCE_DATA_DIR=/data

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY resonance ./resonance
COPY static ./static
RUN pip install --no-cache-dir . \
    && addgroup --system resonance \
    && adduser --system --ingroup resonance --home /nonexistent --no-create-home resonance \
    && mkdir -p /data \
    && chown resonance:resonance /data

VOLUME ["/data"]
EXPOSE 8080
USER resonance
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2)"]
STOPSIGNAL SIGTERM
CMD ["uvicorn", "resonance.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8080", "--proxy-headers"]
