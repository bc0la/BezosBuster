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
# Pipes "y" twice: once for regions confirmation, once for "use default creds?"
COPY <<'PACUWRAP' /usr/local/bin/pacu-run
#!/bin/sh
printf 'y\ny\n' | /opt/venv/bin/pacu --session bezosbuster --exec --module-name "$2" --set-regions all -q
PACUWRAP
RUN chmod +x /usr/local/bin/pacu-run

# powerpipe-run wrapper: manages steampipe service lifecycle around powerpipe.
# Each invocation picks a random port so concurrent module runs don't collide.
# Uses STEAMPIPE_DATABASE_PORT env var (works with both steampipe and powerpipe).
COPY <<'WRAPPER' /usr/local/bin/powerpipe-run
#!/bin/bash
PORT=$((19200 + (RANDOM % 10000)))
export STEAMPIPE_DATABASE_PORT=$PORT
steampipe service start --database-listen local >/dev/null 2>&1
for i in $(seq 1 10); do
  (echo >/dev/tcp/127.0.0.1/$PORT) 2>/dev/null && break
  sleep 1
done
powerpipe "$@" --var "database=postgres://steampipe:@127.0.0.1:${PORT}/steampipe"
rc=$?
steampipe service stop >/dev/null 2>&1
exit $rc
WRAPPER
RUN chmod +x /usr/local/bin/powerpipe-run

ENV PATH=/opt/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Switch to non-root for everything else.
USER bb
WORKDIR /home/bb

# Steampipe AWS plugin + mods (must be installed by the same user that runs steampipe)
RUN steampipe plugin install aws \
 && mkdir -p /home/bb/mods \
 && git clone --depth=1 https://github.com/turbot/steampipe-mod-aws-insights /home/bb/mods/steampipe-mod-aws-insights \
 && git clone --depth=1 https://github.com/turbot/steampipe-mod-aws-perimeter /home/bb/mods/steampipe-mod-aws-perimeter

# Pre-create pacu session so the wrapper can find it at runtime
RUN printf 'exit\n' | /opt/venv/bin/pacu --new-session bezosbuster 2>/dev/null || true

COPY --from=build /out/bezosbuster /usr/local/bin/bezosbuster

WORKDIR /data
ENTRYPOINT ["bezosbuster"]
CMD ["--help"]
