ARG KALI_TOOLS_IMAGE=ai-security/kali-tools:latest
FROM ${KALI_TOOLS_IMAGE}

USER root

ARG NODE_VERSION=22.11.0
ARG PI_CODING_AGENT_VERSION=0.74.0

RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
      amd64) node_arch="x64" ;; \
      arm64) node_arch="arm64" ;; \
      *) echo "unsupported architecture: $arch" >&2; exit 1 ;; \
    esac; \
    curl -fsSLo /tmp/node.tar.gz "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-${node_arch}.tar.gz"; \
    tar -xzf /tmp/node.tar.gz -C /usr/local --strip-components=1; \
    rm -f /tmp/node.tar.gz; \
    node --version; \
    npm --version; \
    npm install -g "@earendil-works/pi-coding-agent@${PI_CODING_AGENT_VERSION}"; \
    apt-get update; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends sqlmap; \
    apt-get clean; \
    rm -rf /var/lib/apt/lists/*

WORKDIR /workspace/work
