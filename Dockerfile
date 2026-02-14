# Dockerfile (Multi-stage)
# Final image: Debian Bookworm Slim (no Python runtime needed - CLI is a PyInstaller binary)

# ------------------------------------------------------------------------------
# Stage 1: tool-builder
# Downloads pre-built binaries for Gitleaks, Opengrep, and OSV-Scanner
# ------------------------------------------------------------------------------
FROM python:3.13-slim-bookworm AS tool-builder

# Install curl and tar to download binaries
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    tar \
    && rm -rf /var/lib/apt/lists/*

# Define tool versions
ARG GITLEAKS_VERSION=8.24.2
ARG OPENGREP_VERSION=v1.16.0
ARG OSV_SCANNER_VERSION=2.3.3

# Download Gitleaks
RUN curl -sfL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
    -o gitleaks.tar.gz && \
    tar -xzf gitleaks.tar.gz -C /usr/local/bin/ gitleaks && \
    rm gitleaks.tar.gz

# Download Opengrep (Standalone binary)
RUN curl -sfL "https://github.com/opengrep/opengrep/releases/download/${OPENGREP_VERSION}/opengrep_manylinux_x86" \
    -o /usr/local/bin/opengrep && \
    chmod +x /usr/local/bin/opengrep

# Download OSV-Scanner (Standalone binary)
RUN curl -sfL "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_linux_amd64" \
    -o /usr/local/bin/osv-scanner && \
    chmod +x /usr/local/bin/osv-scanner

# ------------------------------------------------------------------------------
# Stage 2: kics-builder
# Builds KICS from source (Go) because no standalone binary is released
# ------------------------------------------------------------------------------
FROM golang:1.23 AS kics-builder
ARG KICS_VERSION=v2.1.5
# Use a specific UPX version (latest stable as of Feb 2026)
ARG UPX_VERSION=4.2.4

# Install build tools.
# curl and xz-utils are needed to download and extract UPX.
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    xz-utils \
    && rm -rf /var/lib/apt/lists/*

# Download and install UPX from GitHub releases
# Debian Bookworm (golang:1.23 base) does not include upx-ucl in main repos
RUN curl -sfL "https://github.com/upx/upx/releases/download/v${UPX_VERSION}/upx-${UPX_VERSION}-amd64_linux.tar.xz" \
    -o upx.tar.xz && \
    tar -xf upx.tar.xz && \
    mv upx-${UPX_VERSION}-amd64_linux/upx /usr/local/bin/ && \
    rm -rf upx.tar.xz upx-${UPX_VERSION}-amd64_linux

WORKDIR /build

# Clone KICS (shallow clone to save bandwidth/time)
RUN git clone --depth 1 --branch ${KICS_VERSION} https://github.com/Checkmarx/kics.git .

# Build CLI binary (strip debug symbols)
RUN go build -o /usr/local/bin/kics -ldflags="-s -w" ./cmd/console

# Compress checks binary to reduce size
RUN upx -9 /usr/local/bin/kics

# ------------------------------------------------------------------------------
# Stage 3: cli-builder
# Builds the Gerion CLI python application into a standalone binary
# ------------------------------------------------------------------------------
FROM python:3.13-slim-bookworm AS cli-builder

COPY . /gerion_cli
WORKDIR /gerion_cli

# Install system build dependencies (objdump is required by PyInstaller)
RUN apt-get update && apt-get install -y --no-install-recommends \
    binutils \
    && rm -rf /var/lib/apt/lists/*

# Install python build dependencies
RUN pip install poetry pyinstaller && \
    poetry config virtualenvs.create false && \
    poetry install --no-interaction --no-ansi && \
    # Remove Premium code for Standard Image (Open Core)
    rm -rf gerion_cli/pro && \
    pyinstaller --name gerion --distpath /usr/local/bin/ --onefile gerion_cli/main.py

# ------------------------------------------------------------------------------
# Stage 4: final
# Runtime image - minimal dependencies + all binaries
# ------------------------------------------------------------------------------
FROM debian:bookworm-slim

# Install Runtime Dependencies
# - git: Required by Gitleaks and Opengrep
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy tools & CLI (consolidated COPY to reduce layers)
COPY --from=tool-builder \
    /usr/local/bin/gitleaks \
    /usr/local/bin/opengrep \
    /usr/local/bin/osv-scanner \
    /usr/local/bin/
    
COPY --from=kics-builder /usr/local/bin/kics /usr/local/bin/
COPY --from=cli-builder /usr/local/bin/gerion /usr/local/bin/

# KICS requires the queries directory to exist (uses embedded rules but validates the path)
# User Setup
RUN mkdir -p /usr/local/bin/assets/queries && \
    groupadd -r gerion && useradd -r -g gerion -d /home/gerion -m gerion && \
    mkdir -p /code /output && chown -R gerion:gerion /code /output

WORKDIR /code
ENV PATH="/usr/local/bin:${PATH}"
ENV FORCE_COLOR=1

USER gerion
ENTRYPOINT ["gerion"]
CMD ["--help"]