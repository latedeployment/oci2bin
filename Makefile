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

MAKEINFO  ?= $(or $(shell command -v texi2any 2>/dev/null),\
               $(shell command -v makeinfo 2>/dev/null),\
               makeinfo)
MAN_DIR    = doc
INFO_DIR   = doc

.PHONY: all clean polyglot loader loader-x86_64 loader-aarch64 loader-all \
        doc install uninstall test test-unit test-unit-aarch64 \
        test-integration test-integration-redis test-integration-nginx \
        test-c test-c-aarch64 test-python

all: polyglot

# ── Documentation ─────────────────────────────────────────────────────────────

# Build the GNU info file from the Texinfo source.
# Requires: makeinfo (texinfo package).
doc: $(INFO_DIR)/oci2bin.info

$(INFO_DIR)/oci2bin.info: $(INFO_DIR)/oci2bin.texi
	@if command -v $(MAKEINFO) >/dev/null 2>&1; then \
	  $(MAKEINFO) --no-split -o $@ $<; \
	else \
	  echo "warning: makeinfo/texi2any not found; install the 'texinfo' package to build oci2bin.info"; \
	fi

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
	install -d $(PREFIX)/share/man/man1
	install -m 644 $(MAN_DIR)/oci2bin.1 $(PREFIX)/share/man/man1/oci2bin.1
	if [ -f $(INFO_DIR)/oci2bin.info ]; then \
	  install -d $(PREFIX)/share/info; \
	  install -m 644 $(INFO_DIR)/oci2bin.info $(PREFIX)/share/info/oci2bin.info; \
	  install-info --dir-file=$(PREFIX)/share/info/dir $(PREFIX)/share/info/oci2bin.info 2>/dev/null || true; \
	fi
	@echo "Installed. Run: oci2bin <image>"

uninstall:
	rm -f $(PREFIX)/bin/oci2bin
	rm -rf $(PREFIX)/share/oci2bin
	rm -f $(PREFIX)/share/man/man1/oci2bin.1
	-install-info --delete --dir-file=$(PREFIX)/share/info/dir \
	  $(PREFIX)/share/info/oci2bin.info 2>/dev/null || true
	rm -f $(PREFIX)/share/info/oci2bin.info

clean:
	rm -rf build $(OUTPUT)
	rm -f $(INFO_DIR)/oci2bin.info

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
