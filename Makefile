GITLEAKS_VERSION    := 8.30.1
OPENGREP_VERSION    := 1.16.5
OSV_SCANNER_VERSION := 2.3.5
KICS_VERSION        := 2.1.20

OS   := $(shell uname -s | tr '[:upper:]' '[:lower:]')
ARCH := $(shell uname -m)

# Normalize arch names
ifeq ($(ARCH),x86_64)
  ARCH_AMD := amd64
  ARCH_X64 := x64
else ifeq ($(ARCH),aarch64)
  ARCH_AMD := arm64
  ARCH_X64 := arm64
else ifeq ($(ARCH),arm64)
  ARCH_AMD := arm64
  ARCH_X64 := arm64
endif

BIN_DIR := $(HOME)/.local/bin

# Pre-compute download URLs (ifeq must live outside recipes)
GITLEAKS_URL := https://github.com/gitleaks/gitleaks/releases/download/v$(GITLEAKS_VERSION)/gitleaks_$(GITLEAKS_VERSION)_$(OS)_$(ARCH_X64).tar.gz

ifeq ($(OS),linux)
  OPENGREP_URL     := https://github.com/opengrep/opengrep/releases/download/v$(OPENGREP_VERSION)/opengrep_manylinux_x86
  OSV_SCANNER_URL  := https://github.com/google/osv-scanner/releases/download/v$(OSV_SCANNER_VERSION)/osv-scanner_linux_$(ARCH_AMD)
else ifeq ($(OS),darwin)
  OPENGREP_URL     := https://github.com/opengrep/opengrep/releases/download/v$(OPENGREP_VERSION)/opengrep_osx
  OSV_SCANNER_URL  := https://github.com/google/osv-scanner/releases/download/v$(OSV_SCANNER_VERSION)/osv-scanner_darwin_$(ARCH_AMD)
endif

.PHONY: all install install-python install-tools \
        install-gitleaks install-opengrep install-osv-scanner install-kics \
        gitleaks opengrep osv-scanner kics \
        uninstall uninstall-gitleaks uninstall-opengrep uninstall-osv-scanner uninstall-kics \
        check clean help

all: install

# ──────────────────────────────────────────────────────────────────────────────
# Full install: Python deps + external scanner binaries
# ──────────────────────────────────────────────────────────────────────────────
install: install-python install-tools
	@echo ""
	@echo "✓ Gerion CLI ready. Run: gerion --help"

# ──────────────────────────────────────────────────────────────────────────────
# Python / Poetry
# ──────────────────────────────────────────────────────────────────────────────
install-python:
	@echo "→ Installing Python dependencies..."
	@poetry install --no-interaction -q
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
	    echo "→ Installing Gitleaks v$(GITLEAKS_VERSION)..."; \
	    mkdir -p $(BIN_DIR); \
	    curl -sfL "$(GITLEAKS_URL)" -o /tmp/gitleaks.tar.gz || { echo "  ✗ Download failed: $(GITLEAKS_URL)"; exit 1; }; \
	    tar -xzf /tmp/gitleaks.tar.gz -C $(BIN_DIR) gitleaks; \
	    rm /tmp/gitleaks.tar.gz; \
	    echo "  ✓ gitleaks → $(BIN_DIR)/gitleaks"; \
	fi

install-opengrep:
	@if $(BIN_DIR)/opengrep --version 2>&1 | grep -qF "$(OPENGREP_VERSION)"; then \
	    echo "  ✓ opengrep v$(OPENGREP_VERSION) already installed, skipping"; \
	else \
	    echo "→ Installing Opengrep v$(OPENGREP_VERSION)..."; \
	    mkdir -p $(BIN_DIR); \
	    curl -sfL "$(OPENGREP_URL)" -o $(BIN_DIR)/opengrep; \
	    chmod +x $(BIN_DIR)/opengrep; \
	    echo "  ✓ opengrep → $(BIN_DIR)/opengrep"; \
	fi

install-osv-scanner:
	@if $(BIN_DIR)/osv-scanner --version 2>&1 | grep -qF "$(OSV_SCANNER_VERSION)"; then \
	    echo "  ✓ osv-scanner v$(OSV_SCANNER_VERSION) already installed, skipping"; \
	else \
	    echo "→ Installing OSV-Scanner v$(OSV_SCANNER_VERSION)..."; \
	    mkdir -p $(BIN_DIR); \
	    curl -sfL "$(OSV_SCANNER_URL)" -o $(BIN_DIR)/osv-scanner; \
	    chmod +x $(BIN_DIR)/osv-scanner; \
	    echo "  ✓ osv-scanner → $(BIN_DIR)/osv-scanner"; \
	fi

install-kics:
	@if [ -x "$(BIN_DIR)/kics" ] && $(BIN_DIR)/kics version 2>&1 | grep -qF "$(KICS_VERSION)" && [ -d "$(BIN_DIR)/assets/queries" ] && [ "$$(ls -A $(BIN_DIR)/assets/queries)" ]; then \
	    echo "  ✓ kics v$(KICS_VERSION) and queries already installed, skipping"; \
	else \
	    if ! command -v go >/dev/null 2>&1; then \
	        echo "  ✗ KICS must be built from source but Go is not installed."; \
	        echo "    Install Go: https://go.dev/doc/install"; \
	        echo "    Or via your package manager:"; \
	        echo "      Debian/Ubuntu:  sudo apt install golang-go"; \
	        echo "      Fedora:         sudo dnf install golang"; \
	        echo "      Arch:           sudo pacman -S go"; \
	        echo "      macOS:          brew install go"; \
	        exit 1; \
	    fi; \
	    echo "→ Building KICS v$(KICS_VERSION) from source (no prebuilt binary available)..."; \
	    mkdir -p $(BIN_DIR); \
	    rm -rf /tmp/kics-src; \
	    git -c advice.detachedHead=false clone --depth 1 --branch v$(KICS_VERSION) https://github.com/Checkmarx/kics.git /tmp/kics-src || { echo "  ✗ Clone failed"; exit 1; }; \
	    cd /tmp/kics-src && go build -o $(BIN_DIR)/kics \
	        -ldflags="-s -w -X github.com/Checkmarx/kics/v2/internal/constants.Version=$(KICS_VERSION)" \
	        ./cmd/console || { echo "  ✗ Build failed"; exit 1; }; \
	    mkdir -p $(BIN_DIR)/assets; \
	    cp -r /tmp/kics-src/assets/queries $(BIN_DIR)/assets/queries; \
	    rm -rf /tmp/kics-src; \
	    echo "  ✓ kics → $(BIN_DIR)/kics"; \
	fi


# ──────────────────────────────────────────────────────────────────────────────
# Verify all tools are available
# ──────────────────────────────────────────────────────────────────────────────
check:
	@echo "Checking installed tools..."
	@gerion --version      >/dev/null 2>&1 && echo "  ✓ gerion"      || echo "  ✗ gerion (run: make install-python)"
	@gitleaks version      >/dev/null 2>&1 && echo "  ✓ gitleaks"    || echo "  ✗ gitleaks (run: make gitleaks)"
	@opengrep --version    >/dev/null 2>&1 && echo "  ✓ opengrep"    || echo "  ✗ opengrep (run: make opengrep)"
	@osv-scanner --version >/dev/null 2>&1 && echo "  ✓ osv-scanner" || echo "  ✗ osv-scanner (run: make osv-scanner)"
	@kics version          >/dev/null 2>&1 && echo "  ✓ kics"        || echo "  ✗ kics (run: make kics)"

uninstall: uninstall-gitleaks uninstall-opengrep uninstall-osv-scanner uninstall-kics
	@pip uninstall -y gerion-cli 2>/dev/null || true
	@poetry env remove --all 2>/dev/null || true
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
	@echo "  make install-python      Install Python dependencies via Poetry"
	@echo "  make gitleaks            Install Gitleaks only"
	@echo "  make opengrep            Install Opengrep only"
	@echo "  make osv-scanner         Install OSV-Scanner only"
	@echo "  make kics                Install KICS only"
	@echo "  make uninstall           Uninstall everything"
	@echo "  make uninstall-gitleaks  Uninstall Gitleaks only"
	@echo "  make uninstall-opengrep  Uninstall Opengrep only"
	@echo "  make uninstall-osv-scanner Uninstall OSV-Scanner only"
	@echo "  make uninstall-kics      Uninstall KICS only"
	@echo "  make check               Verify all tools are in PATH"
	@echo "  make clean               Uninstall everything + remove venv"
