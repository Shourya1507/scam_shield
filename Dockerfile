# ── Stage 1: builder ──────────────────────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ── Stage 2: runtime ─────────────────────────────────────────────────────────
FROM python:3.11-slim

LABEL maintainer="ScamShield AI Team"
LABEL description="Multi-agent scam protection system"

# Create a non-root user
RUN useradd -m -u 1000 scamshield

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application code
COPY . .

# Ensure logs directory exists and is writable
RUN mkdir -p /app/logs && chown -R scamshield:scamshield /app

USER scamshield

# Environment defaults (override via docker run -e or docker-compose)
ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    GUARDIAN_DEFAULT_CONTACT="+1-555-0100" \
    MCP_HOST=0.0.0.0 \
    MCP_PORT=8000

# ── Exposed ports ─────────────────────────────────────────────────────────────
# 8000: MCP server (HTTP mode — for Cursor/Claude Desktop over TCP)
# 8080: Webhook ingestion endpoint
EXPOSE 8000 8080

# ── Default command: run the webhook server by default ───────────────────────
CMD ["python", "-m", "cli.scamshield_cli", "serve-webhook", "--type", "email"]
