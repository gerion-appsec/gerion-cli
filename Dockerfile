
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

# Stage 2: Builder stage to Gerion cli
FROM python:3.13-alpine AS cli-builder
ADD . /gerion_cli/
WORKDIR /gerion_cli

# Install Gerion cli
RUN set -eux && \
    apk add binutils && \
    python -m venv venv && \
    source venv/bin/activate && \
    pip install pyinstaller poetry && \
    poetry install && \
    pyinstaller --name gerion --distpath /usr/local/bin/ --onefile gerion_cli/main.py

# Stage 2: Final stage with only Trivy and Gitleaks
FROM alpine:latest AS final

# Copy only the necessary executables from the builder stage
COPY --from=builder /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=builder /usr/local/bin/gitleaks /usr/local/bin/gitleaks
COPY --from=cli-builder /usr/local/bin/gerion /usr/local/bin/gerion

# Installing base software
RUN apk add git

# Define entrypoint to run Trivy by default (can be overridden)
ENTRYPOINT ["/usr/local/bin/gerion"]

# TO-DO: Specify the user to run the container process and set workspace (best practice for security)
# When running the container, you can use the `--user` flag:
# docker run --rm --user=1000:1000 -v "$PWD:/code" security-tools fs /code
# or define a user in a base image like alpine in the final stage if needed.
# USER nonroot