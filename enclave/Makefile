# Makefile for the in-enclave boot binary + EIF assembly steps.
#
# `make boot` — build the boot binary inside the reproducible Docker
#               container. Produces `enclave/build/boot.bin`. Works
#               anywhere Docker runs (macOS / Linux dev / CI).
#
# `make verify` — build twice, in independent containers, and diff the
#                 boot binaries bit-exactly. Pass = reproducibility is
#                 holding; fail = something in the build picked up a
#                 non-determinism (timestamp, path, env var).
#
# `make eif` — assemble the full EIF using `nitro-cli build-enclave`.
#              REQUIRES an AWS Nitro-enabled instance + `nitro-cli` on
#              PATH. Not runnable on the dev macOS / CI host. Fails fast
#              with a clear message there.

SHELL := /bin/bash
.PHONY: boot verify eif clean help

DOCKER ?= docker
NITRO_CLI ?= nitro-cli
BUILD_DIR ?= build
DOCKERFILE ?= Dockerfile.eif
IMAGE_TAG ?= qfc-enclave-boot:m3-skeleton

help:
	@echo "M3 enclave build targets:"
	@echo "  make boot     - build boot binary inside Docker (anywhere)"
	@echo "  make verify   - two independent rebuilds, diff bit-exact"
	@echo "  make eif      - assemble full EIF (REQUIRES nitro-cli + AWS host)"
	@echo "  make clean    - rm -rf build/"

boot:
	@mkdir -p $(BUILD_DIR)
	# `--context` points at the repo root because the Dockerfile references
	# `../crates` for the workspace path-dep crates.
	$(DOCKER) build \
	    --file $(DOCKERFILE) \
	    --target runtime \
	    --tag $(IMAGE_TAG) \
	    --build-arg SOURCE_DATE_EPOCH=1700000000 \
	    ..
	$(DOCKER) create --name qfc-extract $(IMAGE_TAG) > /dev/null
	$(DOCKER) cp qfc-extract:/boot.bin $(BUILD_DIR)/boot.bin
	$(DOCKER) rm qfc-extract > /dev/null
	@sha256sum $(BUILD_DIR)/boot.bin

verify:
	@echo "Building twice and diffing bit-exact..."
	$(MAKE) boot BUILD_DIR=$(BUILD_DIR)/a IMAGE_TAG=$(IMAGE_TAG)-a
	$(MAKE) boot BUILD_DIR=$(BUILD_DIR)/b IMAGE_TAG=$(IMAGE_TAG)-b
	@if cmp -s $(BUILD_DIR)/a/boot.bin $(BUILD_DIR)/b/boot.bin; then \
	    echo "PASS: reproducible build, sha256 = $$(sha256sum $(BUILD_DIR)/a/boot.bin | cut -d' ' -f1)"; \
	else \
	    echo "FAIL: builds differ"; \
	    diff <(xxd $(BUILD_DIR)/a/boot.bin | head) <(xxd $(BUILD_DIR)/b/boot.bin | head); \
	    exit 1; \
	fi

eif:
	@which $(NITRO_CLI) > /dev/null 2>&1 || { \
	    echo "ERROR: nitro-cli not found on PATH."; \
	    echo "       The EIF assembly step requires an AWS Nitro-enabled"; \
	    echo "       host (EC2 m5n / m6i / similar). It does NOT run on"; \
	    echo "       macOS dev / regular CI. See enclave/Dockerfile.eif"; \
	    echo "       comment for the nitro-cli invocation."; \
	    exit 1; \
	}
	$(MAKE) boot
	$(NITRO_CLI) build-enclave \
	    --docker-uri $(IMAGE_TAG) \
	    --output-file $(BUILD_DIR)/qfc-server-wallet.eif
	$(NITRO_CLI) describe-eif --eif-path $(BUILD_DIR)/qfc-server-wallet.eif

clean:
	rm -rf $(BUILD_DIR)
