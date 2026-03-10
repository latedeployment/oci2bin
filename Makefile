CC_X86_64  = gcc
# Use native gcc on aarch64 host; cross-compiler when targeting aarch64 from x86_64
ifeq ($(shell uname -m),aarch64)
CC_AARCH64       = gcc
CFLAGS_AARCH64   =
else
CC_AARCH64       = aarch64-linux-gnu-gcc
# Sysroot for the aarch64 cross-compiler — Fedora package: sysroot-aarch64-fc43-glibc
AARCH64_SYSROOT ?= /usr/aarch64-redhat-linux/sys-root/fc43
CFLAGS_AARCH64   = --sysroot=$(AARCH64_SYSROOT) -isystem $(AARCH64_SYSROOT)/usr/include
endif
CC         = gcc
CFLAGS     = -static -O2 -s -Wall -Wextra
IMAGE     ?= alpine:latest
OUTPUT    ?= oci2bin.img
PREFIX    ?= /usr/local
ARCH      ?= $(shell uname -m)

QEMU_AARCH64 ?= qemu-aarch64-static

TESTS_DIR          = tests
TEST_C_BIN         = build/test_c_units
TEST_C_BIN_AARCH64 = build/test_c_units-aarch64

.PHONY: all clean polyglot loader loader-x86_64 loader-aarch64 loader-all \
        install uninstall test test-unit test-unit-aarch64 \
        test-integration test-integration-redis test-integration-nginx \
        test-c test-c-aarch64 test-python

all: polyglot

loader: build/loader-$(ARCH)

loader-x86_64: build/loader-x86_64

loader-aarch64: build/loader-aarch64

loader-all: build/loader-x86_64 build/loader-aarch64

build/loader-x86_64: src/loader.c
	@mkdir -p build
	$(CC_X86_64) $(CFLAGS) -o $@ $<
	@echo "Loader (x86_64): $$(ls -lh $@ | awk '{print $$5}')"

build/loader-aarch64: src/loader.c
	@mkdir -p build
	$(CC_AARCH64) $(CFLAGS_AARCH64) $(CFLAGS) -o $@ $<
	@echo "Loader (aarch64): $$(ls -lh $@ | awk '{print $$5}')"

polyglot: build/loader-$(ARCH)
	python3 scripts/build_polyglot.py \
		--loader build/loader-$(ARCH) \
		--image $(IMAGE) \
		--output $(OUTPUT)

# Install the CLI tool system-wide.
# Bakes the current loader binary into the install; run 'make loader' first.
install: build/loader-$(ARCH)
	install -d $(PREFIX)/bin
	install -d $(PREFIX)/share/oci2bin/scripts
	install -d $(PREFIX)/share/oci2bin/build
	install -d $(PREFIX)/share/oci2bin/src
	install -m 755 oci2bin $(PREFIX)/bin/oci2bin
	install -m 644 scripts/build_polyglot.py $(PREFIX)/share/oci2bin/scripts/
	install -m 644 src/loader.c $(PREFIX)/share/oci2bin/src/
	[ -f build/loader-x86_64  ] && install -m 755 build/loader-x86_64  $(PREFIX)/share/oci2bin/build/ || true
	[ -f build/loader-aarch64 ] && install -m 755 build/loader-aarch64 $(PREFIX)/share/oci2bin/build/ || true
	sed -i 's|OCI2BIN_HOME:-\$$SCRIPT_DIR|OCI2BIN_HOME:-$(PREFIX)/share/oci2bin|' \
		$(PREFIX)/bin/oci2bin
	@echo "Installed. Run: oci2bin <image>"

uninstall:
	rm -f $(PREFIX)/bin/oci2bin
	rm -rf $(PREFIX)/share/oci2bin

clean:
	rm -rf build $(OUTPUT)

# ── Test targets ──────────────────────────────────────────────────────────────

test: test-unit test-integration

test-unit: test-c test-python

test-unit-aarch64: test-c-aarch64 test-python

test-c: $(TEST_C_BIN)
	@echo "=== C unit tests (x86_64) ==="
	@$(TEST_C_BIN)

$(TEST_C_BIN): $(TESTS_DIR)/test_c_units.c src/loader.c
	@mkdir -p build
	$(CC) -static -Wno-return-local-addr -o $@ $<

test-c-aarch64: $(TEST_C_BIN_AARCH64)
	@echo "=== C unit tests (aarch64 via $(QEMU_AARCH64)) ==="
	@$(QEMU_AARCH64) $(TEST_C_BIN_AARCH64)

$(TEST_C_BIN_AARCH64): $(TESTS_DIR)/test_c_units.c src/loader.c
	@mkdir -p build
	$(CC_AARCH64) $(CFLAGS_AARCH64) -static -Wno-return-local-addr -o $@ $<

test-python:
	@echo "=== Python unit tests ==="
	python3 -m unittest discover -s tests -p 'test_build.py' -v
	@echo "=== Polyglot structure tests ==="
	python3 -m unittest tests.test_polyglot.TestExistingPolyglot -v

test-integration: test-integration-redis test-integration-nginx polyglot
	@echo "=== Runtime integration tests ==="
	@bash $(TESTS_DIR)/test_runtime.sh
	@echo "=== Build integration tests ==="
	python3 -m unittest tests.test_polyglot.TestBuildPolyglotIntegration -v

test-integration-redis:
	@echo "=== Redis integration test ==="
	@bash $(TESTS_DIR)/test_integration_redis.sh

test-integration-nginx:
	@echo "=== nginx integration test ==="
	@bash $(TESTS_DIR)/test_integration_nginx.sh
