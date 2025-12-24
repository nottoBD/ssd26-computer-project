BASH_DIR = bash
RESET_SCRIPT = $(BASH_DIR)/1-reset.sh
PKI_SCRIPT = $(BASH_DIR)/2-pki_setup.sh
RUN_SCRIPT = $(BASH_DIR)/3-run.sh

.DEFAULT_GOAL := all
.PHONY: all pki run clean help

all: clean pki run

clean:
	@echo "Running reset..."
	@bash $(RESET_SCRIPT)

pki: clean
	@echo "Running PKI setup..."
	@bash $(PKI_SCRIPT)

run:
	@echo "Running the project..."
	@bash $(RUN_SCRIPT)

# Show help
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  all     : Run reset, pki, and run sequentially (full clean setup and launch) [default]"
	@echo "  pki     : Run 1-reset.sh then 2-pki_setup.sh (clean then generate PKI)"
	@echo "  run     : Run 3-run.sh (starts services via Docker Compose)"
	@echo "  clean   : Run 1-reset.sh (clean setup)"
	@echo "  help    : Show this help message"
