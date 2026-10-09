# Tunnex web SPA — build with Node, serve static files with nginx (non-root).
# Build context is the repo root.

# Ship editor clients from the exact control-plane source, independently of
# package-manager release lag. Downloads remain behind the CP HTTPS authority.
# Cross-compile this same client set once on the build host, rather than
# repeating it under QEMU for each nginx runtime architecture.
FROM --platform=$BUILDPLATFORM golang:1.26.9-alpine@sha256:cdfd4fe2da6b225d8b40c6b7a105736e548e83ff56d5d8f9394446eeb5eb84e0 AS editor-client
WORKDIR /src/apps/cli
COPY apps/cli/ ./
COPY packages/apptransport/ /src/packages/apptransport/
ARG VERSION=dev
RUN mkdir -p /editor-client && for os in darwin linux; do for arch in amd64 arm64; do \
    CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -mod=readonly -trimpath -buildvcs=false \
    -ldflags="-s -w -X main.version=${VERSION}" -o /editor-client/tunnex-$os-$arch ./cmd/tunnex && \
    sha256sum /editor-client/tunnex-$os-$arch | cut -d ' ' -f 1 > /editor-client/tunnex-$os-$arch.sha256; \
    done; done

# The SPA is static output shared by both runtime architectures. Keep Node,
# TypeScript and Vite native too; only the final nginx image is target-specific.
FROM --platform=$BUILDPLATFORM node:24.21.0-alpine@sha256:ebfe2f90462722a7a4de65e91990e97fe0d401c70e0e762c5b53302f905ec1c1 AS build
WORKDIR /app
RUN corepack enable

# Install workspace deps (web + shared) with good layer caching.
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml* ./
COPY apps/web/package.json apps/web/package.json
COPY packages/shared/package.json packages/shared/package.json
RUN pnpm install --filter @tunnex/web... --frozen-lockfile

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
FROM nginxinc/nginx-unprivileged:1.30.5-alpine@sha256:4714e0b1b2577eaa1a6131d07c958b67f0eb68e6d0521e90c6e5287db8cf0bc5
COPY deploy/nginx/spa.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/apps/web/dist /usr/share/nginx/html
COPY --from=editor-client /editor-client /usr/share/nginx/html/editor-client
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=5 \
  CMD wget -qO- http://127.0.0.1:8080/ >/dev/null 2>&1 || exit 1
