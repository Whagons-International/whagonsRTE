#
# WhagonsRTE Dockerfile (multi-stage)
# - Builds a static Go binary
# - Runs it in a small runtime image with CA certificates
#

FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS builder

WORKDIR /src

# Build deps
RUN apk add --no-cache ca-certificates git

# Go module deps (cached layer)
COPY go.mod go.sum ./
RUN go mod download

# Source
COPY . .

# Build a static binary (no libc dependency)
ARG TARGETOS=linux
ARG TARGETARCH=amd64
ENV CGO_ENABLED=0
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/whagonsrte .


FROM alpine:3.20

WORKDIR /app

# Runtime deps: CA certs for TLS connections (e.g., Postgres over TLS)
RUN apk add --no-cache ca-certificates tzdata && update-ca-certificates

# Run as non-root (app may write .whagons-config.json on first boot)
RUN addgroup -S app && adduser -S app -G app && chown -R app:app /app

COPY --from=builder /out/whagonsrte /app/whagonsrte
COPY --from=builder /src/super_admins.yaml /app/super_admins.yaml
RUN chmod +x /app/whagonsrte && chown app:app /app/whagonsrte /app/super_admins.yaml

# Default server port (can be overridden via SERVER_PORT env var)
EXPOSE 8082

# Common config env vars (optional; app also supports .env or .whagons-config.json)
ENV SERVER_PORT=8082

USER app

CMD ["/app/whagonsrte"]

