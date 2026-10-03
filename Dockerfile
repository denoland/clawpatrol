# Runtime image for a prebuilt clawpatrol binary.
#
# Build a Linux binary first, then build the image from the same directory:
#   CGO_ENABLED=0 GOOS=linux GOARCH=amd64 make build
#   docker build -t clawpatrol:dev .
FROM debian:stable-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    iproute2 \
    netcat-openbsd \
    sqlite3 \
  && rm -rf /var/lib/apt/lists/*

COPY clawpatrol /usr/local/bin/clawpatrol

ENTRYPOINT ["/usr/local/bin/clawpatrol"]
