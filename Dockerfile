# Dockerfile (Multi-stage, multi-arch: linux/amd64 + linux/arm64)
#
# Stages:
#   tool-builder  Downloads prebuilt Gitleaks, Opengrep and OSV-Scanner binaries and
#                 verifies each against a pinned SHA-256 (runs on the build host).
#   kics-builder  Cross-compiles KICS from source (no prebuilt binaries are published),
#                 asserting the tag resolves to the pinned commit.
#   cli-reqs      Exports the locked, hashed runtime requirements from uv.lock.
#   cli-wheel     Builds the pure-Python gerion-cli wheel.
#   final         python:3.13-slim + the scanners + the CLI installed as a normal
#                 Python package (no PyInstaller, so no per-run self-extraction).
#
# The final stage stays on Python 3.13: the premium image builds FROM it and installs
# a native wheel built for that interpreter.

# ------------------------------------------------------------------------------
# Stage 1: tool-builder
# ------------------------------------------------------------------------------
FROM --platform=$BUILDPLATFORM python:3.13-slim-trixie@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90 AS tool-builder

ARG TARGETARCH

ARG GITLEAKS_VERSION=8.30.1
ARG GITLEAKS_SHA256_AMD64=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb
ARG GITLEAKS_SHA256_ARM64=e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080

ARG OPENGREP_VERSION=v1.33.1
ARG OPENGREP_SHA256_AMD64=46e8133cc490f9f50518061590ce2f6be5a08afaeda034471c0ceda4b3899808
ARG OPENGREP_SHA256_ARM64=d1433f63a90b8bc0b6ad4b498a13b372b856ce9a754a43484ba4920fe2d76dcf

ARG OSV_SCANNER_VERSION=2.7.0
ARG OSV_SCANNER_SHA256_AMD64=160c6253e2922e9e0a6a9771c5c4c40a4b3c6090b34a3cdd5e80c96cc2e4218b
ARG OSV_SCANNER_SHA256_ARM64=4061ef4c021ed3c47f203b818f337e351336cc5cd67c0274fc36bd1dfc728dd7

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    tar \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /dl

RUN set -eu; \
    case "${TARGETARCH}" in \
      amd64) GL_ARCH=x64;   GL_SHA="${GITLEAKS_SHA256_AMD64}";     OG_ARCH=x86;     OG_SHA="${OPENGREP_SHA256_AMD64}"; \
             OSV_ARCH=amd64; OSV_SHA="${OSV_SCANNER_SHA256_AMD64}" ;; \
      arm64) GL_ARCH=arm64; GL_SHA="${GITLEAKS_SHA256_ARM64}";     OG_ARCH=aarch64; OG_SHA="${OPENGREP_SHA256_ARM64}"; \
             OSV_ARCH=arm64; OSV_SHA="${OSV_SCANNER_SHA256_ARM64}" ;; \
      *) echo "Unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o gitleaks.tar.gz "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${GL_ARCH}.tar.gz"; \
    echo "${GL_SHA}  gitleaks.tar.gz" | sha256sum -c -; \
    curl -fsSL -o opengrep "https://github.com/opengrep/opengrep/releases/download/${OPENGREP_VERSION}/opengrep_manylinux_${OG_ARCH}"; \
    echo "${OG_SHA}  opengrep" | sha256sum -c -; \
    curl -fsSL -o osv-scanner "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_linux_${OSV_ARCH}"; \
    echo "${OSV_SHA}  osv-scanner" | sha256sum -c -; \
    mkdir -p /out; \
    tar -xzf gitleaks.tar.gz -C /out gitleaks; \
    install -m 0755 opengrep osv-scanner /out/

# ------------------------------------------------------------------------------
# Stage 2: kics-builder
# ------------------------------------------------------------------------------
FROM --platform=$BUILDPLATFORM golang:1.27-trixie@sha256:c47c3fda018d13d43a6bf5ebac3e5bba8a23a35782aa4faf531afaf47c64c39f AS kics-builder

ARG TARGETARCH
ARG KICS_VERSION=v2.2.0
ARG KICS_COMMIT=453066aa9c66014ad7aee7dd0149ba1944c78050

WORKDIR /build

# Tags are mutable: pin the commit and fail the build if the tag moved.
RUN git -c advice.detachedHead=false clone --depth 1 --branch "${KICS_VERSION}" https://github.com/Checkmarx/kics.git . && \
    test "$(git rev-parse HEAD)" = "${KICS_COMMIT}"

RUN CGO_ENABLED=0 GOOS=linux GOARCH="${TARGETARCH}" go build -trimpath \
    -ldflags="-s -w -X github.com/Checkmarx/kics/v2/internal/constants.Version=${KICS_VERSION}" \
    -o /out/kics ./cmd/console

# ------------------------------------------------------------------------------
# Stage 3: cli-reqs
# Locked runtime requirements with hashes. Only depends on pyproject.toml/uv.lock,
# so the dependency layer in the final image is cached when only source changes.
# ------------------------------------------------------------------------------
FROM --platform=$BUILDPLATFORM python:3.13-slim-trixie@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90 AS cli-reqs

COPY --from=ghcr.io/astral-sh/uv:0.13.7@sha256:96f40d3904aad8d0bd010539001d36c8e2188b981e1334471a90c4a1d93bb490 /uv /usr/local/bin/uv

WORKDIR /src
COPY pyproject.toml uv.lock ./
RUN uv export --locked --no-dev --no-emit-project --format requirements-txt -o /requirements.txt

# ------------------------------------------------------------------------------
# Stage 4: cli-wheel
# ------------------------------------------------------------------------------
FROM --platform=$BUILDPLATFORM python:3.13-slim-trixie@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90 AS cli-wheel

COPY --from=ghcr.io/astral-sh/uv:0.13.7@sha256:96f40d3904aad8d0bd010539001d36c8e2188b981e1334471a90c4a1d93bb490 /uv /usr/local/bin/uv

WORKDIR /src
COPY pyproject.toml uv.lock README.md LICENSE NOTICE ./
COPY gerion_cli ./gerion_cli

# Open-core guard: a local gerion_cli/pro/ must never be packaged in the public image.
RUN rm -rf gerion_cli/pro && uv build --wheel --out-dir /wheels

# ------------------------------------------------------------------------------
# Stage 5: final
# ------------------------------------------------------------------------------
FROM python:3.13-slim-trixie@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90

# - git: required by Gitleaks and Opengrep
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* && \
    # /code is a bind mount never owned by the container user; without this git
    # refuses to read repository metadata ("dubious ownership").
    git config --system --add safe.directory '*'

COPY --from=tool-builder /out/gitleaks /out/opengrep /out/osv-scanner /usr/local/bin/
COPY --from=kics-builder /out/kics /usr/local/bin/kics

# KICS queries: the runner auto-detects <dir of kics binary>/assets/queries
COPY --from=kics-builder /build/assets/queries /usr/local/bin/assets/queries

# uv is only mounted for the install steps and never lands in the image. Bytecode is
# compiled here because the runtime user cannot write .pyc files. Dependencies come
# first (hash-checked) so they stay cached when only the source changes.
RUN --mount=from=ghcr.io/astral-sh/uv:0.13.7@sha256:96f40d3904aad8d0bd010539001d36c8e2188b981e1334471a90c4a1d93bb490,source=/uv,target=/usr/local/bin/uv \
    --mount=from=cli-reqs,source=/requirements.txt,target=/tmp/requirements.txt \
    uv pip install --system --no-cache --compile-bytecode --require-hashes -r /tmp/requirements.txt

RUN --mount=from=ghcr.io/astral-sh/uv:0.13.7@sha256:96f40d3904aad8d0bd010539001d36c8e2188b981e1334471a90c4a1d93bb490,source=/uv,target=/usr/local/bin/uv \
    --mount=from=cli-wheel,source=/wheels,target=/wheels \
    uv pip install --system --no-cache --compile-bytecode --no-deps /wheels/*.whl

# User Setup
RUN groupadd -r gerion && useradd -r -g gerion -d /home/gerion -m gerion && \
    mkdir -p /code /output && chown -R gerion:gerion /code /output

WORKDIR /code
ENV FORCE_COLOR=1
ENV XDG_CACHE_HOME=/tmp/.cache
ENV HOME=/tmp

USER gerion
ENTRYPOINT ["gerion"]
CMD ["--help"]
