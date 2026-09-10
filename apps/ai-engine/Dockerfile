FROM golang:1.27.0-alpine AS build
RUN apk add --no-cache git python3 build-base
WORKDIR /build
RUN git init source && git -C source remote add origin https://github.com/maximhq/bifrost.git && git -C source fetch --depth=1 origin 9537b2fadf42af90eb34ed47d3d4252e1beff4a0
COPY build.py saved_probe.go ./extension/
ENV CGO_ENABLED=1
RUN python3 extension/build.py /build/source /build/engine
RUN git -C /build/source show 9537b2fadf42af90eb34ed47d3d4252e1beff4a0:LICENSE > /build/BIFROST-LICENSE
RUN git -C /build/source show 9537b2fadf42af90eb34ed47d3d4252e1beff4a0:THIRD_PARTY_NOTICES.md > /build/BIFROST-THIRD-PARTY-NOTICES.md

FROM maximhq/bifrost:v2.0.0@sha256:cf71be9fad4e0749b6e26cbb774c687413dad9a0970b83f4e1dadb6f503ea208
COPY --from=build /build/engine /app/main
COPY --from=build /build/BIFROST-LICENSE /app/BIFROST-LICENSE
COPY --from=build /build/BIFROST-THIRD-PARTY-NOTICES.md /app/BIFROST-THIRD-PARTY-NOTICES.md
