# Tunnex edge reverse proxy (non-root).
# Routes the SPA (/) to the web service and the API (/healthz, /api) to the API.

FROM nginxinc/nginx-unprivileged:1.27-alpine
COPY deploy/nginx/nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=5 \
  CMD wget -qO- http://127.0.0.1:8080/healthz >/dev/null 2>&1 || exit 1
