# Multi-stage Dockerfile for StellaraeSecure admin frontend

# --- Build stage ---
FROM node:22-bookworm-slim AS builder

WORKDIR /app

# Build-time environment used by Vite.
ARG VITE_OAUTH2_API_BASE_URL=http://localhost:4000
ARG VITE_STAFFDB_API_BASE_URL=http://localhost:3000
ARG VITE_AUTH_HANDOFF_START_URL=http://localhost:3000/auth/start?return_to=http://localhost:8080/auth/callback
ARG VITE_ALLOW_BOOTSTRAP_LOGIN=false
ARG VITE_AUTH_HANDOFF_REQUIRE_STATE=true
ARG VITE_AUTH_HANDOFF_MAX_SKEW_SECONDS=300
ARG VITE_PERSIST_SENSITIVE_SESSION_FIELDS=false

ENV VITE_OAUTH2_API_BASE_URL=${VITE_OAUTH2_API_BASE_URL}
ENV VITE_STAFFDB_API_BASE_URL=${VITE_STAFFDB_API_BASE_URL}
ENV VITE_AUTH_HANDOFF_START_URL=${VITE_AUTH_HANDOFF_START_URL}
ENV VITE_ALLOW_BOOTSTRAP_LOGIN=${VITE_ALLOW_BOOTSTRAP_LOGIN}
ENV VITE_AUTH_HANDOFF_REQUIRE_STATE=${VITE_AUTH_HANDOFF_REQUIRE_STATE}
ENV VITE_AUTH_HANDOFF_MAX_SKEW_SECONDS=${VITE_AUTH_HANDOFF_MAX_SKEW_SECONDS}
ENV VITE_PERSIST_SENSITIVE_SESSION_FIELDS=${VITE_PERSIST_SENSITIVE_SESSION_FIELDS}

COPY package.json package-lock.json ./
RUN npm ci

COPY . .
RUN npm run build

# --- Runtime stage ---
FROM nginx:1.28-bookworm

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=builder /app/dist /usr/share/nginx/html

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget -q -O /dev/null http://localhost/healthz || exit 1
