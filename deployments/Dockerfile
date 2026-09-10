# syntax=docker/dockerfile:1

# ---- build ----------------------------------------------------------------
FROM golang:1.25-alpine AS builder

WORKDIR /src

# Cache module downloads separately from the sources.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
ENV CGO_ENABLED=0 GOOS=linux
RUN go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/iam-service ./cmd/iam-service \
 && go build -trimpath -ldflags "-s -w" -o /out/echo-backend ./cmd/echo

# ---- runtime --------------------------------------------------------------
FROM alpine:3.20 AS runtime

RUN apk add --no-cache ca-certificates wget \
 && addgroup -g 10001 -S iam \
 && adduser -u 10001 -S -G iam -h /app iam \
 && mkdir -p /app /var/lib/iam/keys \
 && chown -R iam:iam /app /var/lib/iam

COPY --from=builder /out/iam-service /app/iam-service
COPY --from=builder /out/echo-backend /app/echo-backend
COPY --chown=iam:iam configs/config.yaml /app/configs/config.yaml

WORKDIR /app
USER 10001:10001
EXPOSE 8080 9090

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1:9090/readyz || exit 1

ENTRYPOINT ["/app/iam-service"]
CMD ["serve"]

# ---- demo backend ---------------------------------------------------------
# A tiny echo service used to exercise the Nginx auth_request integration.
FROM runtime AS backend
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1:8080/healthz || exit 1
ENTRYPOINT ["/app/echo-backend"]
CMD ["--addr", ":8080"]
