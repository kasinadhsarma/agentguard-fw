# AgentGuard proxy. Build:  docker build -t agentguard:0.5.0 .
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app
COPY requirements-server.txt .
RUN pip install -r requirements-server.txt

COPY agentguard ./agentguard
# files copied from a host with strict permissions (mode 600) would be
# unreadable by the unprivileged user below
RUN chmod -R a+rX /app

# run as an unprivileged user; /var/log/agentguard holds the audit chain
RUN useradd --system --uid 10001 --no-create-home guard \
 && mkdir -p /var/log/agentguard \
 && chown guard /var/log/agentguard
USER 10001

EXPOSE 8000

# uvicorn reads WEB_CONCURRENCY as the worker count. Start with one worker
# per CPU core. Shared Redis (AGENTGUARD_REDIS_URL) is REQUIRED when this is
# above 1, because each worker would otherwise keep its own sessions.
ENV WEB_CONCURRENCY=2

HEALTHCHECK --interval=15s --timeout=3s --retries=3 \
  CMD python -c "import urllib.request as u; u.urlopen('http://127.0.0.1:8000/health', timeout=2)"

CMD ["uvicorn", "agentguard.proxy:app", "--host", "0.0.0.0", "--port", "8000", \
     "--no-server-header", "--timeout-keep-alive", "30"]
