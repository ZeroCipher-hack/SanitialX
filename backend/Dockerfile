# ── Stage 1: Build virtual environment ──────────────────────────────────────
FROM python:3.13-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -r requirements.txt

# ── Stage 2: Final runtime container ───────────────────────────────────────
FROM python:3.13-slim AS runner

WORKDIR /app

# Install runtime libpq for PostgreSQL asyncpg connection
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy virtualenv from builder stage
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
ENV PYTHONPATH=/app

# Create non-root user for security invariant compliance
RUN groupadd -g 1001 sentinelx && \
    useradd -u 1001 -g sentinelx -s /bin/bash -m sentinelx

COPY . /app
RUN chown -R sentinelx:sentinelx /app

USER sentinelx

EXPOSE 8000

CMD ["uvicorn", "main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
