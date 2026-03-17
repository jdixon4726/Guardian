# Guardian — Multi-stage build
# Stage 1: Build React UI
FROM node:20-alpine AS ui-build
WORKDIR /app/ui
COPY ui/package*.json ./
RUN npm ci
COPY ui/ ./
RUN npm run build

# Stage 2: Python application
FROM python:3.13-slim AS runtime
WORKDIR /app

# Install dependencies
COPY pyproject.toml setup.cfg ./
COPY src/ src/
RUN pip install --no-cache-dir -e .

# Copy config, policies, scenarios
COPY config/ config/
COPY policies/ policies/
COPY scenarios/ scenarios/
COPY simulator/ simulator/

# Copy built UI into FastAPI static directory
COPY --from=ui-build /app/ui/dist/ src/guardian/api/static/

# Create data directory for SQLite databases and audit logs
RUN mkdir -p /app/data

ENV GUARDIAN_CONFIG_DIR=/app/config
ENV GUARDIAN_POLICIES_DIR=/app/policies
ENV GUARDIAN_AUDIT_LOG=/app/data/audit.jsonl
ENV GUARDIAN_CORS_ORIGINS=*
ENV GUARDIAN_JSON_LOGS=true

# Render uses PORT env var
ENV PORT=8000
EXPOSE 8000

CMD uvicorn guardian.api.app:app --host 0.0.0.0 --port ${PORT}
