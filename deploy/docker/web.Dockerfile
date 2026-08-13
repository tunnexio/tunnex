# Tunnex web SPA — build with Node, serve static files with nginx (non-root).
# Build context is the repo root.

FROM node:20-alpine AS build
WORKDIR /app
RUN corepack enable

# Install workspace deps (web + shared) with good layer caching.
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml* ./
COPY apps/web/package.json apps/web/package.json
COPY packages/shared/package.json packages/shared/package.json
RUN pnpm install --filter @tunnex/web... --no-frozen-lockfile

COPY packages/shared/ packages/shared/
COPY apps/web/ apps/web/

# The visual-regression gallery is a BUILD-TIME flag, because Vite bakes `import.meta.env` into the bundle.
# Unset here and in every production build, so the route is dead-code-eliminated. Only the `visual` CI job
# (and `make visual` locally) passes 1.
#
# It has to be a BUILD ARG, not a container env var: putting it in .env reaches compose and the running
# container, and arrives far too late — the bundle was already built without the route. That is exactly how
# the first CI run failed, with the gallery specs timing out on an element that had never been compiled in.
ARG VITE_VISUAL_GALLERY=""
ENV VITE_VISUAL_GALLERY=$VITE_VISUAL_GALLERY
RUN pnpm --filter @tunnex/web build

# nginx-unprivileged runs as a non-root user and listens on 8080.
FROM nginxinc/nginx-unprivileged:1.27-alpine
COPY deploy/nginx/spa.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/apps/web/dist /usr/share/nginx/html
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=5 \
  CMD wget -qO- http://127.0.0.1:8080/ >/dev/null 2>&1 || exit 1
