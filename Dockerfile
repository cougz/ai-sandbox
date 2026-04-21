# The cloudflare/sandbox base image ships the container agent that handles
# /ws/pty (terminal), /exec, /files, etc. on port 3000.
# Version 0.8.9 includes @cloudflare/sandbox/opencode integration support.
# Retrigger: CLOUDFLARE_API_TOKEN secret now configured.
FROM docker.io/cloudflare/sandbox:0.8.9

# OpenCode binary location
ENV PATH="/root/.opencode/bin:${PATH}"
# Trust the Cloudflare Zero Trust CA so the container can reach
# Access-protected services (e.g. the MCP server at ai-sandbox.cloudemo.org).
ENV NODE_EXTRA_CA_CERTS="/usr/local/share/ca-certificates/zero_trust_cert.crt"
# Stable location for OpenCode runtime data (sessions, MCP auth, etc.)
ENV XDG_DATA_HOME="/home/user/.opencode-data"

# Cloudflare Zero Trust root CA — required for HTTPS from container to Access-protected origins
COPY chat-config/zero_trust_cert.pem /usr/local/share/ca-certificates/zero_trust_cert.crt
RUN update-ca-certificates

# Extra tools useful in the interactive terminal
RUN apt-get update && apt-get install -y --no-install-recommends \
    vim \
    nano \
    jq \
    htop \
    net-tools \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# Install OpenCode by downloading the pinned release zip directly from GitHub.
# We bypass the opencode.ai/install script because it performs a network call
# to fetch the latest version metadata, which fails in the Workers Builds
# Docker context. Downloading from github.com/releases works fine.
ARG OPENCODE_VERSION=1.14.19
RUN ARCH=$(uname -m) && \
    case "${ARCH}" in \
      x86_64)  OC_ARCH="x64"   ;; \
      aarch64) OC_ARCH="arm64" ;; \
      *) echo "Unsupported arch: ${ARCH}" && exit 1 ;; \
    esac && \
    curl -fsSL --retry 5 --retry-delay 3 --retry-all-errors \
      "https://github.com/anomalyco/opencode/releases/download/v${OPENCODE_VERSION}/opencode-linux-${OC_ARCH}.tar.gz" \
      -o /tmp/opencode.tar.gz && \
    tar -xzf /tmp/opencode.tar.gz -C /usr/local/bin opencode && \
    chmod +x /usr/local/bin/opencode && \
    rm -f /tmp/opencode.tar.gz && \
    opencode --version

# Copy the default OpenCode config (provider/model/MCP are injected at runtime
# by createOpencode() in chat-session.ts, which merges on top of this file)
COPY chat-config/opencode.jsonc /home/user/workspace/opencode.jsonc

# Prepare OpenCode data directory and initialise a git repo (OpenCode uses git
# internally for session snapshots)
RUN mkdir -p /home/user/.opencode-data/opencode \
    && mkdir -p /home/user/workspace \
    && cd /home/user/workspace \
    && git init \
    && git config user.email "sandbox@cloudflare.com" \
    && git config user.name "Sandbox"

WORKDIR /home/user/workspace

# Port 4096: OpenCode HTTP server (proxied by Worker at /chat/oc/*)
# Port 8080: Sandbox container agent (/ws/pty, /exec, /files — kept for /dash terminal)
EXPOSE 4096
EXPOSE 8080
