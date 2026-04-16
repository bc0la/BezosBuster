# syntax=docker/dockerfile:1.6

# ---------- build stage ----------
FROM golang:1.25-bookworm AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/bezosbuster ./cmd/bezosbuster

# ---------- runtime stage ----------
FROM debian:bookworm-slim
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl git python3 python3-pip python3-venv jq unzip sudo \
    && rm -rf /var/lib/apt/lists/*

# Non-root user (steampipe refuses to run as root).
RUN useradd -m -u 1000 -s /bin/bash bb

# Python tools as root (writes to /opt) — ScoutSuite + Pacu in a venv.
RUN python3 -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir scoutsuite pacu termcolor \
 && chmod -R a+rX /opt/venv

# Steampipe (database + plugin engine)
RUN curl -fsSL https://steampipe.io/install/steampipe.sh -o /tmp/steampipe.sh \
 && bash /tmp/steampipe.sh \
 && rm /tmp/steampipe.sh

# Powerpipe (benchmarks + dashboards — replaces `steampipe check`)
RUN curl -fsSL https://powerpipe.io/install/powerpipe.sh -o /tmp/powerpipe.sh \
 && bash /tmp/powerpipe.sh \
 && rm /tmp/powerpipe.sh

# Kingfisher secret scanner (latest release binary)
RUN set -eux; \
    SUFFIX="linux-x64.tgz"; \
    LATEST_URL=$(curl -fsSL https://api.github.com/repos/mongodb/kingfisher/releases/latest \
        | grep -Eo "https://[^\"]*${SUFFIX}"); \
    curl -fsSL "$LATEST_URL" -o /tmp/kingfisher.tgz; \
    cd /tmp && tar -xzf kingfisher.tgz; \
    KF_PATH=$(find /tmp -type f -name 'kingfisher*' -executable -print -quit); \
    mv "$KF_PATH" /usr/local/bin/kingfisher; \
    rm -rf /tmp/kingfisher*

# Blue-CloudPEASS clone (as root, world-readable) + install all Python deps
RUN git clone --depth=1 https://github.com/peass-ng/Blue-CloudPEASS /opt/Blue-CloudPEASS \
 && find /opt/Blue-CloudPEASS -type f -name '*.py' -exec chmod +x {} \; \
 && if [ -f /opt/Blue-CloudPEASS/requirements.txt ]; then \
      /opt/venv/bin/pip install --no-cache-dir -r /opt/Blue-CloudPEASS/requirements.txt; \
    fi

# Blue-CloudPEASS wrapper (the AWS entry point is Blue-AWSPEAS.py at repo root)
RUN printf '#!/bin/sh\nexec python3 /opt/Blue-CloudPEASS/Blue-AWSPEAS.py "$@"\n' > /usr/local/bin/blue-cloudpeass \
 && chmod +x /usr/local/bin/blue-cloudpeass

# pacu wrapper for non-interactive single-module runs
# Session "bezosbuster" is pre-created during build (see below).
# Pipes unlimited "y" via `yes` to handle all interactive prompts.
COPY <<'PACUWRAP' /usr/local/bin/pacu-run
#!/bin/sh
yes | /opt/venv/bin/pacu --session bezosbuster --exec --module-name "$2" --set-regions all
PACUWRAP
RUN chmod +x /usr/local/bin/pacu-run

# powerpipe-run wrapper: ensures steampipe service is running on default
# port (9193), then runs powerpipe. Service is left running for other modules.
COPY <<'WRAPPER' /usr/local/bin/powerpipe-run
#!/bin/bash
steampipe service start --database-listen local 2>/dev/null
for i in $(seq 1 15); do
  (echo >/dev/tcp/127.0.0.1/9193) 2>/dev/null && break
  sleep 2
done
powerpipe "$@"
WRAPPER
RUN chmod +x /usr/local/bin/powerpipe-run

ENV PATH=/opt/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Switch to non-root for everything else.
USER bb
WORKDIR /home/bb

# Steampipe AWS plugin + mods (must be installed by the same user that runs steampipe)
RUN steampipe plugin install aws \
 && mkdir -p /home/bb/mods \
 && git clone --depth=1 https://github.com/turbot/steampipe-mod-aws-perimeter /home/bb/mods/steampipe-mod-aws-perimeter

# Pre-create pacu session so the wrapper can find it at runtime
RUN printf 'exit\n' | /opt/venv/bin/pacu --new-session bezosbuster 2>/dev/null || true

COPY --from=build /out/bezosbuster /usr/local/bin/bezosbuster

WORKDIR /data
ENTRYPOINT ["bezosbuster"]
CMD ["--help"]
