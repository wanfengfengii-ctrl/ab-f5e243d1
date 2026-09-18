# syntax=docker/dockerfile:1
#
# Build a fully static binary (CGO disabled) so the runtime image needs only
# CA-free base content and the binary. All Go dependencies are vendored, so
# building this image requires no network access beyond the base images.

FROM golang:1.27-alpine AS build
WORKDIR /src

# Vendored modules make the build hermetic and network-independent.
COPY go.mod go.sum ./
COPY vendor ./vendor
COPY cmd ./cmd
COPY internal ./internal

# Build every role into the same binary; the runtime role is selected by ROLE.
RUN CGO_ENABLED=0 GOOS=linux go build -mod=vendor \
    -trimpath -ldflags="-s -w" -o /out/telemetry ./cmd/telemetry \
 && CGO_ENABLED=0 GOOS=linux go build -mod=vendor \
    -trimpath -ldflags="-s -w" -o /out/verify ./cmd/verify

FROM alpine:3.20 AS runtime
# The service makes no outbound TLS calls, so no extra packages (and no build-
# time network access) are required beyond the base image.
RUN addgroup -S telemetry && adduser -S -G telemetry telemetry
WORKDIR /app
COPY --from=build /out/telemetry /app/telemetry
COPY --from=build /out/verify /app/verify
USER telemetry
EXPOSE 8080
ENTRYPOINT ["/app/telemetry"]
