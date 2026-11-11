GITLEAKS_VERSION    := 8.30.1
OPENGREP_VERSION    := 1.33.1
OSV_SCANNER_VERSION := 2.7.0
KICS_VERSION        := 2.2.0
KICS_COMMIT         := 453066aa9c66014ad7aee7dd0149ba1944c78050

OS   := $(shell uname -s | tr '[:upper:]' '[:lower:]')
ARCH := $(shell uname -m)

BIN_DIR := $(HOME)/.local/bin

# Per-platform asset names and pinned SHA-256 checksums. Every download is verified
# against these before it is installed. Supported: linux/darwin on x86_64/arm64.
ifeq ($(OS)-$(ARCH),linux-x86_64)
  GITLEAKS_ASSET     := gitleaks_$(GITLEAKS_VERSION)_linux_x64.tar.gz
  GITLEAKS_SHA256    := 551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb
  OPENGREP_ASSET     := opengrep_manylinux_x86
  OPENGREP_SHA256    := 46e8133cc490f9f50518061590ce2f6be5a08afaeda034471c0ceda4b3899808
  OSV_SCANNER_ASSET  := osv-scanner_linux_amd64
  OSV_SCANNER_SHA256 := 160c6253e2922e9e0a6a9771c5c4c40a4b3c6090b34a3cdd5e80c96cc2e4218b
else ifeq ($(OS)-$(ARCH),linux-aarch64)
  GITLEAKS_ASSET     := gitleaks_$(GITLEAKS_VERSION)_linux_arm64.tar.gz
  GITLEAKS_SHA256    := e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080
  OPENGREP_ASSET     := opengrep_manylinux_aarch64
  OPENGREP_SHA256    := d1433f63a90b8bc0b6ad4b498a13b372b856ce9a754a43484ba4920fe2d76dcf
  OSV_SCANNER_ASSET  := osv-scanner_linux_arm64
  OSV_SCANNER_SHA256 := 4061ef4c021ed3c47f203b818f337e351336cc5cd67c0274fc36bd1dfc728dd7
else ifeq ($(OS)-$(ARCH),darwin-x86_64)
  GITLEAKS_ASSET     := gitleaks_$(GITLEAKS_VERSION)_darwin_x64.tar.gz
  GITLEAKS_SHA256    := dfe101a4db2255fc85120ac7f3d25e4342c3c20cf749f2c20a18081af1952709
  OPENGREP_ASSET     := opengrep_osx_x86
  OPENGREP_SHA256    := c3bd18e0d898d44e28419d95dad57c8928bb46ab32889a0ee1f72a87ad9627af
  OSV_SCANNER_ASSET  := osv-scanner_darwin_amd64
  OSV_SCANNER_SHA256 := e82c5df7ab0a42dff29a1cd0660711447b56b4c0483ff66ad8634df10fd81a45
else ifeq ($(OS)-$(ARCH),darwin-arm64)
  GITLEAKS_ASSET     := gitleaks_$(GITLEAKS_VERSION)_darwin_arm64.tar.gz
  GITLEAKS_SHA256    := b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5
  OPENGREP_ASSET     := opengrep_osx_arm64
  OPENGREP_SHA256    := a17c1881bb40e3214266a7a291cf4f2ae3bc56c1715628b5712d2ec816bc3e2d
  OSV_SCANNER_ASSET  := osv-scanner_darwin_arm64
  OSV_SCANNER_SHA256 := d4926ef8da134332543be276dff157e4c170f99ad91fc48e89448a8816bdf70b
else
  UNSUPPORTED := echo "  ✗ Unsupported platform: $(OS)/$(ARCH)"; exit 1;
endif

GITLEAKS_URL    := https://github.com/gitleaks/gitleaks/releases/download/v$(GITLEAKS_VERSION)/$(GITLEAKS_ASSET)
OPENGREP_URL    := https://github.com/opengrep/opengrep/releases/download/v$(OPENGREP_VERSION)/$(OPENGREP_ASSET)
OSV_SCANNER_URL := https://github.com/google/osv-scanner/releases/download/v$(OSV_SCANNER_VERSION)/$(OSV_SCANNER_ASSET)

# macOS ships shasum, most Linux distros ship sha256sum.
SHA256_CMD := $(if $(shell command -v sha256sum 2>/dev/null),sha256sum,shasum -a 256)

# $(call FETCH,<url>,<outfile>,<sha256>): download (fail on HTTP errors) then verify the checksum.
# The file is only used by the recipe after this succeeds.
FETCH = curl -fsSL "$(1)" -o "$(2)" || { echo "  ✗ Download failed: $(1)"; exit 1; }; \
	echo "$(3)  $(2)" | $(SHA256_CMD) -c - >/dev/null || { echo "  ✗ SHA-256 mismatch for $(1)"; exit 1; }

.PHONY: all install install-python install-tools \
        install-gitleaks install-opengrep install-osv-scanner install-kics \
        gitleaks opengrep osv-scanner kics \
        uninstall uninstall-gitleaks uninstall-opengrep uninstall-osv-scanner uninstall-kics \
        check test lint clean help

all: install

# ──────────────────────────────────────────────────────────────────────────────
# Full install: Python deps + external scanner binaries
# ──────────────────────────────────────────────────────────────────────────────
install: install-python install-tools
	@echo ""
	@echo "✓ Gerion CLI ready. Run: gerion --help"

# ──────────────────────────────────────────────────────────────────────────────
# Python / uv
# ──────────────────────────────────────────────────────────────────────────────
install-python:
	@echo "→ Installing Python dependencies..."
	@uv sync -q
	@echo "  ✓ Python dependencies installed"

# ──────────────────────────────────────────────────────────────────────────────
# External scanner tools
# ──────────────────────────────────────────────────────────────────────────────
install-tools: install-gitleaks install-opengrep install-osv-scanner install-kics

gitleaks:    install-gitleaks
opengrep:    install-opengrep
osv-scanner: install-osv-scanner
kics:        install-kics

install-gitleaks:
	@if $(BIN_DIR)/gitleaks version 2>&1 | grep -qF "$(GITLEAKS_VERSION)"; then \
	    echo "  ✓ gitleaks v$(GITLEAKS_VERSION) already installed, skipping"; \
	else \
	    $(UNSUPPORTED) \
	    echo "→ Installing Gitleaks v$(GITLEAKS_VERSION)..."; \
	    tmp=$$(mktemp -d) || exit 1; \
	    trap 'rm -rf "$$tmp"' EXIT; \
	    mkdir -p $(BIN_DIR); \
	    $(call FETCH,$(GITLEAKS_URL),$$tmp/gitleaks.tar.gz,$(GITLEAKS_SHA256)); \
	    tar -xzf "$$tmp/gitleaks.tar.gz" -C "$$tmp" gitleaks; \
	    install -m 0755 "$$tmp/gitleaks" $(BIN_DIR)/gitleaks; \
	    echo "  ✓ gitleaks → $(BIN_DIR)/gitleaks"; \
	fi

install-opengrep:
	@if $(BIN_DIR)/opengrep --version 2>&1 | grep -qF "$(OPENGREP_VERSION)"; then \
	    echo "  ✓ opengrep v$(OPENGREP_VERSION) already installed, skipping"; \
	else \
	    $(UNSUPPORTED) \
	    echo "→ Installing Opengrep v$(OPENGREP_VERSION)..."; \
	    tmp=$$(mktemp -d) || exit 1; \
	    trap 'rm -rf "$$tmp"' EXIT; \
	    mkdir -p $(BIN_DIR); \
	    $(call FETCH,$(OPENGREP_URL),$$tmp/opengrep,$(OPENGREP_SHA256)); \
	    install -m 0755 "$$tmp/opengrep" $(BIN_DIR)/opengrep; \
	    echo "  ✓ opengrep → $(BIN_DIR)/opengrep"; \
	fi

install-osv-scanner:
	@if $(BIN_DIR)/osv-scanner --version 2>&1 | grep -qF "$(OSV_SCANNER_VERSION)"; then \
	    echo "  ✓ osv-scanner v$(OSV_SCANNER_VERSION) already installed, skipping"; \
	else \
	    $(UNSUPPORTED) \
	    echo "→ Installing OSV-Scanner v$(OSV_SCANNER_VERSION)..."; \
	    tmp=$$(mktemp -d) || exit 1; \
	    trap 'rm -rf "$$tmp"' EXIT; \
	    mkdir -p $(BIN_DIR); \
	    $(call FETCH,$(OSV_SCANNER_URL),$$tmp/osv-scanner,$(OSV_SCANNER_SHA256)); \
	    install -m 0755 "$$tmp/osv-scanner" $(BIN_DIR)/osv-scanner; \
	    echo "  ✓ osv-scanner → $(BIN_DIR)/osv-scanner"; \
	fi

install-kics:
	@if [ -x "$(BIN_DIR)/kics" ] && $(BIN_DIR)/kics version 2>&1 | grep -qF "$(KICS_VERSION)" && [ -d "$(BIN_DIR)/assets/queries" ] && [ "$$(ls -A $(BIN_DIR)/assets/queries)" ]; then \
	    echo "  ✓ kics v$(KICS_VERSION) and queries already installed, skipping"; \
	else \
	    if ! command -v go >/dev/null 2>&1; then \
	        echo "  ✗ KICS must be built from source but Go is not installed."; \
	        echo "    Install Go (1.26.2 or newer is required): https://go.dev/doc/install"; \
	        exit 1; \
	    fi; \
	    echo "→ Building KICS v$(KICS_VERSION) from source (no prebuilt binary available)..."; \
	    src=$$(mktemp -d) || exit 1; \
	    trap 'rm -rf "$$src"' EXIT; \
	    mkdir -p $(BIN_DIR); \
	    git -c advice.detachedHead=false clone --depth 1 --branch v$(KICS_VERSION) https://github.com/Checkmarx/kics.git "$$src" || { echo "  ✗ Clone failed"; exit 1; }; \
	    [ "$$(git -C "$$src" rev-parse HEAD)" = "$(KICS_COMMIT)" ] || { echo "  ✗ Tag v$(KICS_VERSION) does not match pinned commit $(KICS_COMMIT)"; exit 1; }; \
	    (cd "$$src" && CGO_ENABLED=0 go build -trimpath -o $(BIN_DIR)/kics \
	        -ldflags="-s -w -X github.com/Checkmarx/kics/v2/internal/constants.Version=$(KICS_VERSION)" \
	        ./cmd/console) || { echo "  ✗ Build failed"; exit 1; }; \
	    mkdir -p $(BIN_DIR)/assets; \
	    rm -rf $(BIN_DIR)/assets/queries; \
	    cp -r "$$src/assets/queries" $(BIN_DIR)/assets/queries; \
	    echo "  ✓ kics → $(BIN_DIR)/kics"; \
	fi


# ──────────────────────────────────────────────────────────────────────────────
# Verify all tools are available
# ──────────────────────────────────────────────────────────────────────────────
check:
	@echo "Checking installed tools..."
	@uv run gerion --version >/dev/null 2>&1 && echo "  ✓ gerion"      || echo "  ✗ gerion (run: make install-python)"
	@gitleaks version      >/dev/null 2>&1 && echo "  ✓ gitleaks"    || echo "  ✗ gitleaks (run: make gitleaks)"
	@opengrep --version    >/dev/null 2>&1 && echo "  ✓ opengrep"    || echo "  ✗ opengrep (run: make opengrep)"
	@osv-scanner --version >/dev/null 2>&1 && echo "  ✓ osv-scanner" || echo "  ✗ osv-scanner (run: make osv-scanner)"
	@kics version          >/dev/null 2>&1 && echo "  ✓ kics"        || echo "  ✗ kics (run: make kics)"

test:
	@uv run pytest

lint:
	@uv run ruff check .

uninstall: uninstall-gitleaks uninstall-opengrep uninstall-osv-scanner uninstall-kics
	@rm -rf .venv
	@echo "✓ Uninstall complete"

uninstall-gitleaks:
	@rm -f $(BIN_DIR)/gitleaks
	@echo "  ✓ gitleaks removed"

uninstall-opengrep:
	@rm -f $(BIN_DIR)/opengrep
	@echo "  ✓ opengrep removed"

uninstall-osv-scanner:
	@rm -f $(BIN_DIR)/osv-scanner
	@echo "  ✓ osv-scanner removed"

uninstall-kics:
	@rm -f $(BIN_DIR)/kics
	@rm -rf $(BIN_DIR)/assets/queries
	@echo "  ✓ kics removed"

clean: uninstall
	@echo "✓ Clean complete"

help:
	@echo "Gerion CLI — Makefile targets"
	@echo ""
	@echo "  make install             Install everything (Python deps + scanner binaries)"
	@echo "  make install-python      Install Python dependencies via uv"
	@echo "  make gitleaks            Install Gitleaks only"
	@echo "  make opengrep            Install Opengrep only"
	@echo "  make osv-scanner         Install OSV-Scanner only"
	@echo "  make kics                Install KICS only"
	@echo "  make uninstall           Uninstall everything"
	@echo "  make uninstall-gitleaks  Uninstall Gitleaks only"
	@echo "  make uninstall-opengrep  Uninstall Opengrep only"
	@echo "  make uninstall-osv-scanner Uninstall OSV-Scanner only"
	@echo "  make uninstall-kics      Uninstall KICS only"
	@echo "  make test                Run the test suite"
	@echo "  make lint                Run ruff"
	@echo "  make check               Verify all tools are in PATH"
	@echo "  make clean               Uninstall everything + remove venv"
