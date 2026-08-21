# Decoy — minimal production image.
# Build:  docker build -t decoy .
# Run:    docker run -d -p 127.0.0.1:8424:8424 -v decoy-data:/data decoy

FROM golang:1.24-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# CGO is required by the mattn/go-sqlite3 driver used in this build.
ARG ISSUER_PUBKEY=""
RUN CGO_ENABLED=1 go build -trimpath \
    -ldflags "-s -w -X main.issuerPublicKeyB64=${ISSUER_PUBKEY}" \
    -o /out/decoy ./cmd/decoy

FROM debian:bookworm-slim
# /data is created and chowned here so a named volume inherits the app user's
# ownership. Without this the volume defaults to root:root and the unprivileged
# process cannot create its database.
RUN useradd -r -u 10001 decoy \
 && apt-get update && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /data \
 && chown decoy:decoy /data
COPY --from=build /out/decoy /usr/local/bin/decoy
USER decoy
VOLUME /data
EXPOSE 8424
ENTRYPOINT ["decoy", "-listen", "0.0.0.0:8424", "-db", "/data/decoy.db", "-license", "/data/decoy-license.key"]
