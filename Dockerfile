# ── OpenEnv Vulnerability Environment — HuggingFace Space Dockerfile ──────────
#
# HF Spaces requires:
#   - Port 7860 exposed
#   - Non-root user (user 1000)
#   - App served at 0.0.0.0:7860

FROM python:3.11-slim

# System deps (none needed — env is stdlib-only; fastapi/uvicorn from pip)
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user required by HF Spaces
RUN useradd -m -u 1000 appuser

WORKDIR /app

# Install Python dependencies first (layer-cached)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY . .

# Drop to non-root user
RUN chown -R appuser:appuser /app
USER appuser

# HF Spaces listens on 7860
EXPOSE 7860

# Health-check so HF Space marks the container ready before pinging /health
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:7860/health || exit 1

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "7860"]
