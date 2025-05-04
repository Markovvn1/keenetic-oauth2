FROM golang:1.23-alpine AS builder

RUN apk add --no-cache ca-certificates git

WORKDIR /build

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN go build -trimpath -ldflags="-s -w" -o keen-proxy cmd/main.go



FROM alpine:3.18

RUN addgroup -S app && adduser -S -G app appuser && apk add --no-cache ca-certificates wget

USER appuser

COPY --from=builder /build/keen-proxy /usr/local/bin/keen-proxy

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s CMD wget -qO- --tries=1 --timeout=2 http://localhost:8080/healthz || exit 1

ENTRYPOINT ["/usr/local/bin/keen-proxy"]
