# syntax=docker/dockerfile:1
#
# Release image. Build from the repository root:
#
#   docker build -f deploy/Dockerfile --build-arg VERSION=v0.1.0 -t belaypoint .
#
# Multi-platform builds (linux/amd64, linux/arm64) cross-compile the Go
# binary on the build platform; only the small final stage runs per platform.

FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
ARG TARGETOS TARGETARCH
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
      -ldflags "-s -w -X github.com/MB512/belaypoint/internal/buildinfo.Version=${VERSION}" \
      -o /out/belaypoint ./cmd/belaypoint

# restic from Alpine (local backend only, no network access needed).
FROM alpine:3.22
ARG VERSION=dev
RUN apk add --no-cache restic \
 && restic version
COPY --from=build /out/belaypoint /app/belaypoint
ENV BELAYPOINT_REPOS_DIR=/repos \
    BELAYPOINT_CONFIG_DIR=/config
EXPOSE 8443
LABEL org.opencontainers.image.title="BelayPoint" \
      org.opencontainers.image.description="Manages a restic rest-server from the LAN: htpasswd users, forget, prune, check" \
      org.opencontainers.image.source="https://github.com/MB512/BelayPoint" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}"
# No USER here: run the container as the owner of the repository files
# ("user:" in compose), see docs/architecture.md.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["/app/belaypoint", "healthcheck"]
ENTRYPOINT ["/app/belaypoint"]
CMD ["serve"]
