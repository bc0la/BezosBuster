# syntax=docker/dockerfile:1.6

# ---------- build stage ----------
FROM golang:1.25-bookworm AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download || true
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/bezosbuster ./cmd/bezosbuster

# ---------- runtime stage ----------
FROM debian:bookworm-slim
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl git python3 python3-pip python3-venv jq unzip \
    && rm -rf /var/lib/apt/lists/*

# Steampipe
RUN curl -fsSL https://steampipe.io/install/steampipe.sh | sh \
 && /usr/local/bin/steampipe plugin install aws

# Python tools: ScoutSuite, Pacu
RUN python3 -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir scoutsuite pacu
ENV PATH=/opt/venv/bin:/usr/local/bin:/usr/bin:/bin

# Blue-CloudPEASS + steampipe mods
RUN mkdir -p /root/mods \
 && git clone --depth=1 https://github.com/peass-ng/Blue-CloudPEASS /opt/Blue-CloudPEASS \
 && ln -sf /opt/Blue-CloudPEASS/src/BluePEASS.py /usr/local/bin/blue-cloudpeass \
 && chmod +x /opt/Blue-CloudPEASS/src/BluePEASS.py \
 && git clone --depth=1 https://github.com/turbot/steampipe-mod-aws-insights /root/mods/steampipe-mod-aws-insights \
 && git clone --depth=1 https://github.com/turbot/steampipe-mod-aws-perimeter /root/mods/steampipe-mod-aws-perimeter

# pacu wrapper for non-interactive single-module runs
RUN printf '#!/bin/sh\nexec pacu --session bezosbuster --module-name "$2" --module-args ""\n' > /usr/local/bin/pacu-run \
 && chmod +x /usr/local/bin/pacu-run

COPY --from=build /out/bezosbuster /usr/local/bin/bezosbuster
WORKDIR /data
ENTRYPOINT ["bezosbuster"]
CMD ["--help"]
