FROM python:3.12-slim
COPY --from=ghcr.io/astral-sh/uv:0.11.29 /uv /uvx /usr/local/bin/
WORKDIR /app
ENV UV_NO_DEV=1 UV_COMPILE_BYTECODE=1 PYTHONUNBUFFERED=1
COPY pyproject.toml uv.lock README.md ./
COPY src/ ./src/
COPY lab-certs/ ./lab-certs/
RUN uv sync --locked --no-dev
ENV PATH="/app/.venv/bin:$PATH"
