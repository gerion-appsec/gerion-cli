# Stage 1: Builder stage to install Trivy and Gitleaks
FROM alpine:latest AS builder

# Define versions as build arguments with default values for flexibility
ARG TRIVY_VERSION=0.61.0
ARG GITLEAKS_VERSION=8.24.2

# Set environment variables for consistent behavior
ENV PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# Update package index and install necessary tools in a single layer
RUN set -eux && \
    apk update && \
    apk add --no-cache curl bash gnupg openssl ca-certificates

# Install Trivy
RUN set -eux && \
    TRIVY_ARCH="Linux-64bit" && \
    TRIVY_DOWNLOAD_URL="https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_${TRIVY_ARCH}.tar.gz" && \
    echo "Downloading Trivy from: ${TRIVY_DOWNLOAD_URL}" && \
    curl -sfL "${TRIVY_DOWNLOAD_URL}" -o /tmp/trivy.tar.gz && \
    tar -xzvf /tmp/trivy.tar.gz -C /usr/local/bin/ && \
    rm /tmp/trivy.tar.gz

# Install Gitleaks
RUN set -eux && \
    GITLEAKS_ARCH="linux_x64" && \
    GITLEAKS_DOWNLOAD_URL="https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_${GITLEAKS_ARCH}.tar.gz" && \
    echo "Downloading Gitleaks from: ${GITLEAKS_DOWNLOAD_URL}" && \
    curl -sfL "${GITLEAKS_DOWNLOAD_URL}" -o /tmp/gitleaks.tar.gz && \
    tar -xzvf /tmp/gitleaks.tar.gz -C /usr/local/bin/ gitleaks && \
    rm /tmp/gitleaks.tar.gz

# Stage 2: Builder stage for Gerion CLI
FROM python:3.13-alpine AS cli-builder

# Copy the entire project
COPY . /gerion_cli/
WORKDIR /gerion_cli

# Install Gerion CLI
RUN set -eux && \
    apk add binutils && \
    python -m venv venv && \
    source venv/bin/activate && \
    pip install pyinstaller poetry && \
    # Regenerate lock file if needed and install dependencies
    poetry lock && \
    poetry install && \
    pyinstaller --name gerion --distpath /usr/local/bin/ --onefile gerion_cli/main.py

# Stage 3: Final stage with Trivy, Gitleaks and Gerion CLI
FROM alpine:latest AS final

# Copy only the necessary executables from the builder stages
COPY --from=builder /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=builder /usr/local/bin/gitleaks /usr/local/bin/gitleaks
COPY --from=cli-builder /usr/local/bin/gerion /usr/local/bin/gerion

# Install base software and create non-root user
RUN set -eux && \
    apk add --no-cache git bash ncurses && \
    addgroup -g 1000 gerion && \
    adduser -D -s /bin/bash -u 1000 -G gerion gerion

# Create working directory and set permissions
RUN mkdir -p /code /output && \
    chown -R gerion:gerion /code /output

# Set working directory
WORKDIR /code

# Set environment variables for better terminal support
ENV TERM=xterm-256color
ENV PYTHONUNBUFFERED=1
ENV FORCE_COLOR=1

# Switch to non-root user for security
USER gerion

# Define entrypoint to run Gerion CLI by default (can be overridden)
ENTRYPOINT ["/usr/local/bin/gerion"]

# Default command (can be overridden)
CMD ["--help"]