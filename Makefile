GITLEAKS_VERSION    := 8.24.2
OPENGREP_VERSION    := 1.16.0
OSV_SCANNER_VERSION := 2.3.3
KICS_VERSION        := 2.1.5

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

.PHONY: all install install-python install-tools \
        install-gitleaks install-opengrep install-osv-scanner install-kics \
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
	poetry install --no-interaction

# ──────────────────────────────────────────────────────────────────────────────
# External scanner tools
# ──────────────────────────────────────────────────────────────────────────────
install-tools: install-gitleaks install-opengrep install-osv-scanner install-kics

install-gitleaks:
	@echo "→ Installing Gitleaks v$(GITLEAKS_VERSION)..."
	@mkdir -p $(BIN_DIR)
	curl -sfL \
	  "https://github.com/gitleaks/gitleaks/releases/download/v$(GITLEAKS_VERSION)/gitleaks_$(GITLEAKS_VERSION)_$(OS)_$(ARCH_X64).tar.gz" \
	  -o /tmp/gitleaks.tar.gz
	tar -xzf /tmp/gitleaks.tar.gz -C $(BIN_DIR) gitleaks
	rm /tmp/gitleaks.tar.gz
	@echo "  ✓ gitleaks → $(BIN_DIR)/gitleaks"

install-opengrep:
	@echo "→ Installing Opengrep v$(OPENGREP_VERSION)..."
	@mkdir -p $(BIN_DIR)
ifeq ($(OS),linux)
	curl -sfL \
	  "https://github.com/opengrep/opengrep/releases/download/v$(OPENGREP_VERSION)/opengrep_manylinux_x86" \
	  -o $(BIN_DIR)/opengrep
else ifeq ($(OS),darwin)
	curl -sfL \
	  "https://github.com/opengrep/opengrep/releases/download/v$(OPENGREP_VERSION)/opengrep_osx" \
	  -o $(BIN_DIR)/opengrep
endif
	chmod +x $(BIN_DIR)/opengrep
	@echo "  ✓ opengrep → $(BIN_DIR)/opengrep"

install-osv-scanner:
	@echo "→ Installing OSV-Scanner v$(OSV_SCANNER_VERSION)..."
	@mkdir -p $(BIN_DIR)
ifeq ($(OS),linux)
	curl -sfL \
	  "https://github.com/google/osv-scanner/releases/download/v$(OSV_SCANNER_VERSION)/osv-scanner_linux_$(ARCH_AMD)" \
	  -o $(BIN_DIR)/osv-scanner
else ifeq ($(OS),darwin)
	curl -sfL \
	  "https://github.com/google/osv-scanner/releases/download/v$(OSV_SCANNER_VERSION)/osv-scanner_darwin_$(ARCH_AMD)" \
	  -o $(BIN_DIR)/osv-scanner
endif
	chmod +x $(BIN_DIR)/osv-scanner
	@echo "  ✓ osv-scanner → $(BIN_DIR)/osv-scanner"

install-kics:
	@echo "→ Installing KICS v$(KICS_VERSION)..."
	@mkdir -p $(BIN_DIR)
ifeq ($(OS),linux)
	curl -sfL \
	  "https://github.com/Checkmarx/kics/releases/download/v$(KICS_VERSION)/kics_$(KICS_VERSION)_linux_$(ARCH_AMD)64.tar.gz" \
	  -o /tmp/kics.tar.gz
	tar -xzf /tmp/kics.tar.gz -C $(BIN_DIR) kics
	rm /tmp/kics.tar.gz
else ifeq ($(OS),darwin)
	curl -sfL \
	  "https://github.com/Checkmarx/kics/releases/download/v$(KICS_VERSION)/kics_$(KICS_VERSION)_darwin_$(ARCH_AMD)64.tar.gz" \
	  -o /tmp/kics.tar.gz
	tar -xzf /tmp/kics.tar.gz -C $(BIN_DIR) kics
	rm /tmp/kics.tar.gz
endif
	@echo "  ✓ kics → $(BIN_DIR)/kics"

# ──────────────────────────────────────────────────────────────────────────────
# Verify all tools are available
# ──────────────────────────────────────────────────────────────────────────────
check:
	@echo "Checking installed tools..."
	@gerion --version       && echo "  ✓ gerion" || echo "  ✗ gerion (run: make install-python)"
	@gitleaks version       && echo "  ✓ gitleaks" || echo "  ✗ gitleaks (run: make install-gitleaks)"
	@opengrep --version     && echo "  ✓ opengrep" || echo "  ✗ opengrep (run: make install-opengrep)"
	@osv-scanner --version  && echo "  ✓ osv-scanner" || echo "  ✗ osv-scanner (run: make install-osv-scanner)"
	@kics version           && echo "  ✓ kics" || echo "  ✗ kics (run: make install-kics)"

clean:
	poetry env remove --all 2>/dev/null || true

help:
	@echo "Gerion CLI — Makefile targets"
	@echo ""
	@echo "  make install            Install everything (Python deps + scanner binaries)"
	@echo "  make install-python     Install Python dependencies via Poetry"
	@echo "  make install-tools      Install all external scanner binaries"
	@echo "  make install-gitleaks   Install Gitleaks only"
	@echo "  make install-opengrep   Install Opengrep only"
	@echo "  make install-osv-scanner Install OSV-Scanner only"
	@echo "  make install-kics       Install KICS only"
	@echo "  make check              Verify all tools are in PATH"
	@echo "  make clean              Remove Poetry virtual environment"
