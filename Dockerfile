# One image, one process. No credential is baked in: the service refuses to start
# without AUTHORATE_TOKEN_SALT and AUTHORATE_SECRET_KEY (see create_app), and no
# layer here sets, copies or defaults either. Pass them at run time.
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
COPY migrations ./migrations
COPY alembic.ini ./
RUN python -m pip install --no-cache-dir .

RUN useradd --create-home --uid 10001 portal \
    && mkdir -p /data/packets \
    && chown -R portal:portal /data
USER portal

ENV AUTHORATE_PACKET_STORE=/data/packets
VOLUME ["/data"]
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=3)"

# Migrations run before the server accepts a connection, and `exec` replaces the
# shell so the process the runtime supervises is the server, not `sh`.
CMD ["sh", "-c", "alembic upgrade head && exec autorate-portal serve --host 0.0.0.0 --port 8000"]
