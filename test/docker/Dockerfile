# Single-image entrypoint switches on $ROLE = gateway | agent so the
# build matrix stays compact. clawpatrol is a static binary; the only
# reason this isn't FROM scratch is the agent role needs /etc/resolv.conf
# resolution and a small set of debug tools (curl, ssh client) for the
# probe scripts.
#
# Built from the repo root via `docker compose build` after `make build`
# has produced ./clawpatrol locally; the binary is COPY'd in to skip the
# Go toolchain dependency at image build time. The Makefile + CI
# workflow keep that ordering.

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    jq \
    libcap2-bin \
    iproute2 \
    iputils-ping \
    openssh-client \
    procps \
    socat \
    && rm -rf /var/lib/apt/lists/*

COPY clawpatrol /usr/local/bin/clawpatrol
RUN chmod +x /usr/local/bin/clawpatrol \
    && setcap cap_net_admin,cap_sys_admin+eip /usr/local/bin/clawpatrol \
    && useradd -m -u 10001 -s /bin/sh e2e

WORKDIR /opt/clawpatrol

COPY test/docker/gateway.hcl /opt/clawpatrol/gateway.hcl
COPY test/docker/entrypoint-gateway.sh /usr/local/bin/entrypoint-gateway.sh
COPY test/docker/entrypoint-agent.sh /usr/local/bin/entrypoint-agent.sh
COPY test/docker/entrypoint-ssh-stub.sh /usr/local/bin/entrypoint-ssh-stub.sh
RUN chmod +x /usr/local/bin/entrypoint-*.sh

# Default to gateway; compose overrides for the agent service.
ENV ROLE=gateway
ENTRYPOINT ["/bin/sh", "-c", "exec /usr/local/bin/entrypoint-${ROLE}.sh \"$@\"", "--"]
