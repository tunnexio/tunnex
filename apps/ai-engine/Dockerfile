# syntax=docker/dockerfile:1
FROM golang:1.27.0-alpine@sha256:4c9fe60190a2a3350ddc51de80d0224b8a6698d12bdfc999fee45ea9d6c46dbc AS build
RUN apk add --no-cache git python3 build-base
WORKDIR /build
RUN git init source && git -C source remote add origin https://github.com/maximhq/bifrost.git && git -C source fetch --depth=1 origin 9537b2fadf42af90eb34ed47d3d4252e1beff4a0
COPY apps/ai-engine/ ./extension/
ARG TARGETARCH
ENV CGO_ENABLED=1
RUN --mount=type=cache,target=/go/pkg/mod,id=ai-engine-mod-${TARGETARCH},sharing=locked \
    --mount=type=cache,target=/root/.cache/go-build,id=ai-engine-build-${TARGETARCH},sharing=locked \
    python3 extension/build.py /build/source /build/engine --test
RUN git -C /build/source show 9537b2fadf42af90eb34ed47d3d4252e1beff4a0:LICENSE > /build/BIFROST-LICENSE
RUN git -C /build/source show 9537b2fadf42af90eb34ed47d3d4252e1beff4a0:THIRD_PARTY_NOTICES.md > /build/BIFROST-THIRD-PARTY-NOTICES.md

FROM maximhq/bifrost:v2.0.0@sha256:cf71be9fad4e0749b6e26cbb774c687413dad9a0970b83f4e1dadb6f503ea208
COPY --from=build /build/engine /app/main
COPY --from=build /build/BIFROST-LICENSE /app/BIFROST-LICENSE
COPY --from=build /build/BIFROST-THIRD-PARTY-NOTICES.md /app/BIFROST-THIRD-PARTY-NOTICES.md
COPY apps/api/internal/aigateway/reference/bifrost-pricing.json apps/api/internal/aigateway/reference/bifrost-model-parameters.json apps/api/internal/aigateway/reference/model-catalog.json apps/api/internal/aigateway/reference/source.pin.json apps/api/internal/aigateway/reference/catalog-manifest.json apps/api/internal/aigateway/reference/LiteLLM-LICENSE /app/catalog/
ARG VERSION=dev
LABEL io.tunnex.engine.upstream.commit="9537b2fadf42af90eb34ed47d3d4252e1beff4a0" \
      io.tunnex.engine.extension.version="v2.0.0-tunnex-native.1" \
      io.tunnex.release.version="${VERSION}"
