FROM golang:1.24-alpine AS builder

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o gate .

FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata && \
    adduser -D -h /app gate && \
    mkdir -p /data && chown gate:gate /data

WORKDIR /app

COPY --from=builder /build/gate /usr/local/bin/gate

USER gate

VOLUME /data
EXPOSE 3000

ENTRYPOINT ["gate"]
