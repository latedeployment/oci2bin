CC       = musl-gcc
CFLAGS   = -static -O2 -s -Wall -Wextra
IMAGE   ?= alpine:latest
OUTPUT  ?= oci2bin.img
PREFIX  ?= /usr/local

TESTS_DIR  = tests
TEST_C_BIN = build/test_c_units

.PHONY: all clean polyglot loader install uninstall \
        test test-unit test-integration test-c test-python

all: polyglot

loader: build/loader

build/loader: src/loader.c
	@mkdir -p build
	$(CC) $(CFLAGS) -o $@ $<
	@echo "Loader: $$(ls -lh $@ | awk '{print $$5}')"

polyglot: build/loader
	python3 scripts/build_polyglot.py \
		--loader build/loader \
		--image $(IMAGE) \
		--output $(OUTPUT)

# Install the CLI tool system-wide.
# Bakes the current loader binary into the install; run 'make loader' first.
install: build/loader
	install -d $(PREFIX)/bin
	install -d $(PREFIX)/share/oci2bin/scripts
	install -d $(PREFIX)/share/oci2bin/build
	install -m 755 polydocker $(PREFIX)/bin/oci2bin
	install -m 644 scripts/build_polyglot.py $(PREFIX)/share/oci2bin/scripts/
	install -m 644 src/loader.c $(PREFIX)/share/oci2bin/src/
	install -m 755 build/loader $(PREFIX)/share/oci2bin/build/
	sed -i 's|OCI2BIN_HOME:-\$$SCRIPT_DIR|OCI2BIN_HOME:-$(PREFIX)/share/oci2bin|' \
		$(PREFIX)/bin/oci2bin
	@echo "Installed. Run: polydocker <image>"

uninstall:
	rm -f $(PREFIX)/bin/oci2bin
	rm -rf $(PREFIX)/share/oci2bin

clean:
	rm -rf build $(OUTPUT)

# ── Test targets ──────────────────────────────────────────────────────────────

test: test-unit test-integration

test-unit: test-c test-python

test-c: $(TEST_C_BIN)
	@echo "=== C unit tests ==="
	@$(TEST_C_BIN)

$(TEST_C_BIN): $(TESTS_DIR)/test_c_units.c src/loader.c
	@mkdir -p build
	$(CC) -static -Wno-return-local-addr -o $@ $<

test-python:
	@echo "=== Python unit tests ==="
	python3 -m unittest discover -s tests -p 'test_build.py' -v
	@echo "=== Polyglot structure tests ==="
	python3 -m unittest tests.test_polyglot.TestExistingPolyglot -v

test-integration: polyglot
	@echo "=== Runtime integration tests ==="
	@bash $(TESTS_DIR)/test_runtime.sh
	@echo "=== Build integration tests ==="
	python3 -m unittest tests.test_polyglot.TestBuildPolyglotIntegration -v
