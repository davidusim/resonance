FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    RESONANCE_DATA_DIR=/data

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY resonance ./resonance
COPY static ./static
RUN pip install --no-cache-dir .

VOLUME ["/data"]
EXPOSE 8080
CMD ["uvicorn", "resonance.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8080", "--proxy-headers"]
