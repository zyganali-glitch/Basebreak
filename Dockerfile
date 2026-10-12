# Basebreak Verification Runtime — Container Image (P-27.02)
# Multi-stage minimal build for reproducible judge & operator deployment.
# Compliant with Zero-Cost Law, secret safety, and rootless security standards.

FROM python:3.11-slim AS runtime

# 1. Environment configuration
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8080 \
    BASEBREAK_HOST=0.0.0.0 \
    BASEBREAK_PORT=8080 \
    BASEBREAK_RUNS_DIR=/data/runs

# 2. Build metadata arguments
ARG BUILD_COMMIT_SHA="UNKNOWN_BUILD_SHA"
ENV BASEBREAK_BUILD_COMMIT_SHA=${BUILD_COMMIT_SHA}

# 3. Create non-root system user and working directory
RUN groupadd -r appgroup --gid 10001 && \
    useradd -r -g appgroup --uid 10001 --create-home --home-dir /home/appuser appuser && \
    mkdir -p /app /data/runs && \
    chown -R appuser:appgroup /app /data/runs

WORKDIR /app

# 4. Copy project source and install package
COPY --chown=appuser:appgroup pyproject.toml README.md LICENSE ./
COPY --chown=appuser:appgroup src ./src

# Install basebreak in standard environment without external dependencies
RUN pip install --no-cache-dir --no-deps -e .

# 5. Switch to non-root user
USER appuser

# 6. Expose default HTTP port
EXPOSE 8080

# 7. Native HTTP health check probe (P-27.04)
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request, sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=3).getcode() == 200 else 1)"

# 8. Container entrypoint
CMD ["python", "-m", "basebreak.cli.main", "serve", "--host", "0.0.0.0", "--port", "8080"]
