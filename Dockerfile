# Stage 1: Build the frontend assets
FROM node:22-slim AS frontend-builder
WORKDIR /app

# Copy package files and configuration needed for npm ci
COPY frontend/package*.json ./
COPY frontend/tsconfig.json ./
COPY frontend/src ./src

# Install dependencies (this will run prepare script which needs tsconfig.json and src/)
RUN npm ci

# Copy remaining files
COPY frontend/ ./

RUN npm run build

# Stage 2: Build the final application with the backend
FROM python:3.12-slim
WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN pip install uv

# backend/pyproject.toml is copied before the sync because the root
# pyproject.toml declares `[tool.uv.workspace] members = ["backend"]`; uv needs
# the member manifest present to resolve the workspace. Keeping it in its own
# layer also means the dependency sync is only re-run when a manifest changes.
COPY pyproject.toml uv.lock ./
COPY backend/pyproject.toml ./backend/
RUN uv sync --no-cache

COPY backend/ ./backend/
RUN mkdir -p /app/frontend
COPY --from=frontend-builder /app/public /app/frontend/public

# The app writes nothing, so it can run unprivileged with a read-only root
# filesystem. HOME points at /tmp, which the Helm chart mounts as an emptyDir.
RUN groupadd --gid 10001 app \
    && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /tmp app
USER 10001:10001
ENV HOME=/tmp

WORKDIR /app/backend

# Expose the port the backend server runs on
EXPOSE 8080

# Invoke the venv's uvicorn directly rather than via `uv run`: uv re-resolves
# and re-syncs the environment on every start, which needs a writable
# /app/.venv and uv cache and therefore breaks under readOnlyRootFilesystem.
CMD ["/app/.venv/bin/uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080"]
