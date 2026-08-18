# Decoy — minimal production image.
# Build:  docker build -t decoy .
# Run:    docker run -d -p 127.0.0.1:8424:8424 -v decoy-data:/data decoy

FROM golang:1.24-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# CGO is required by the mattn/go-sqlite3 driver used in this build.
# (Release note: swapping the driver import to modernc.org/sqlite allows
#  CGO_ENABLED=0 and a fully static binary.)
ARG ISSUER_PUBKEY=""
RUN CGO_ENABLED=1 go build -trimpath \
    -ldflags "-s -w -X main.issuerPublicKeyB64=${ISSUER_PUBKEY}" \
    -o /out/decoy ./cmd/decoy

FROM debian:bookworm-slim
RUN useradd -r -u 10001 decoy \
 && apt-get update && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/decoy /usr/local/bin/decoy
USER decoy
VOLUME /data
EXPOSE 8424
ENTRYPOINT ["decoy", "-listen", "0.0.0.0:8424", "-db", "/data/decoy.db", "-license", "/data/decoy-license.key"]
