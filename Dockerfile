# Dockerfile (Standard)
# Base: Python 3.13 Slim (Debian)

# Stage 1: Builder stage to install Trivy and Gitleaks
FROM python:3.13-slim-bookworm AS builder

# Install build tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    tar \
    git \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Define versions
ARG TRIVY_VERSION=0.61.0
ARG GITLEAKS_VERSION=8.24.2

# Install Trivy (Binary)
RUN TRIVY_ARCH="Linux-64bit" && \
    curl -sfL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_${TRIVY_ARCH}.tar.gz" -o trivy.tar.gz && \
    tar -xzf trivy.tar.gz -C /usr/local/bin/ trivy && \
    rm trivy.tar.gz

# Install Gitleaks (Binary)
RUN GITLEAKS_ARCH="linux_x64" && \
    curl -sfL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_${GITLEAKS_ARCH}.tar.gz" -o gitleaks.tar.gz && \
    tar -xzf gitleaks.tar.gz -C /usr/local/bin/ gitleaks && \
    rm gitleaks.tar.gz

# Stage 2: Build Gerion CLI
COPY . /gerion_cli
WORKDIR /gerion_cli

# Install dependencies and build binary
RUN pip install poetry pyinstaller && \
    poetry config virtualenvs.create false && \
    poetry install --no-interaction --no-ansi && \
    # Remove Premium code for Standard Image (Open Core)
    rm -rf gerion_cli/pro && \
    pyinstaller --name gerion --distpath /usr/local/bin/ --onefile gerion_cli/main.py

# Stage 3: Final Stage
FROM python:3.13-slim-bookworm

# Copy binaries
COPY --from=builder /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=builder /usr/local/bin/gitleaks /usr/local/bin/gitleaks
COPY --from=builder /usr/local/bin/gerion /usr/local/bin/gerion

# Install Runtime Deps & Semgrep (Pinned)
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/* && \
    pip install --no-cache-dir semgrep==1.97.0

# User Setup
RUN groupadd -r gerion && useradd -r -g gerion -d /home/gerion -m gerion
RUN mkdir -p /code /output && chown -R gerion:gerion /code /output

WORKDIR /code
ENV PATH="/usr/local/bin:${PATH}"
ENV FORCE_COLOR=1

USER gerion
ENTRYPOINT ["gerion"]
CMD ["--help"]