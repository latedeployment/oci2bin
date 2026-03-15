CC_X86_64  = gcc
CC_CLANG  ?= clang
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
TEST_TMPDIR       ?= $(CURDIR)/build/test-tmp
TEST_ENV           = TMPDIR=$(TEST_TMPDIR) OCI2BIN_TMPDIR=$(TEST_TMPDIR)

MAKEINFO  ?= $(or $(shell command -v texi2any 2>/dev/null),\
               $(shell command -v makeinfo 2>/dev/null),\
               makeinfo)
MAN_DIR    = doc
INFO_DIR   = doc

LIBKRUN ?= 0
ifeq ($(LIBKRUN),1)
$(info Building with libkrun support (USE_LIBKRUN))
endif

# VM defaults — override at build time:
#   make VM_CPUS=4 VM_MEM_MB=512
VM_CPUS   ?=
VM_MEM_MB ?=
VM_DEFS   :=
ifneq ($(VM_CPUS),)
VM_DEFS += -DDEFAULT_VM_CPUS=$(VM_CPUS)
endif
ifneq ($(VM_MEM_MB),)
VM_DEFS += -DDEFAULT_VM_MEM_MB=$(VM_MEM_MB)
endif

# Kernel download / build (cloud-hypervisor path only)
KERNEL_VERSION = 6.1.166
VMLINUX_OUT    = build/vmlinux

.PHONY: all clean clean-all polyglot loader loader-x86_64 loader-aarch64 loader-all \
        loader-libkrun kernel doc install uninstall test test-unit \
        test-unit-aarch64 test-integration test-integration-redis \
        test-integration-nginx test-integration-services \
        test-c test-c-aarch64 test-python \
        test-vm-unit test-vm \
        lint lint-clang lint-semgrep lint-scan-build

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

# libkrun-enabled loader: links -lkrun, NOT static (libkrun is a dynamic lib)
loader-libkrun: build/loader-libkrun-$(ARCH)

build/loader-libkrun-x86_64: src/loader.c
	@mkdir -p build $(TEST_TMPDIR)
	$(TEST_ENV) $(CC_X86_64) -O2 -s -Wall -Wextra -DUSE_LIBKRUN $(VM_DEFS) -o $@ $< -lkrun
	@echo "Loader/libkrun (x86_64): $$(ls -lh $@ | awk '{print $$5}')"

build/loader-libkrun-aarch64: src/loader.c
	@mkdir -p build $(TEST_TMPDIR)
	$(TEST_ENV) $(CC_AARCH64) $(CFLAGS_AARCH64) -O2 -s -Wall -Wextra -DUSE_LIBKRUN $(VM_DEFS) -o $@ $< -lkrun
	@echo "Loader/libkrun (aarch64): $$(ls -lh $@ | awk '{print $$5}')"

# Kernel fetch / build (cloud-hypervisor path only)
kernel: $(VMLINUX_OUT)

$(VMLINUX_OUT): kernel/microvm.config scripts/fetch_kernel.sh
	bash scripts/fetch_kernel.sh $(KERNEL_VERSION) kernel/microvm.config $@

build/loader-x86_64: src/loader.c
	@mkdir -p build $(TEST_TMPDIR)
	$(TEST_ENV) $(CC_X86_64) $(CFLAGS) $(VM_DEFS) -o $@ $<
	@echo "Loader (x86_64): $$(ls -lh $@ | awk '{print $$5}')"

build/loader-aarch64: src/loader.c
	@mkdir -p build $(TEST_TMPDIR)
	$(TEST_ENV) $(CC_AARCH64) $(CFLAGS_AARCH64) $(CFLAGS) $(VM_DEFS) -o $@ $<
	@echo "Loader (aarch64): $$(ls -lh $@ | awk '{print $$5}')"

polyglot: build/loader-$(ARCH)
	@mkdir -p $(TEST_TMPDIR)
	$(TEST_ENV) python3 scripts/build_polyglot.py \
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
	ln -sf $(PREFIX)/bin/oci2bin $(PREFIX)/bin/oci2vm
	install -m 644 scripts/build_polyglot.py $(PREFIX)/share/oci2bin/scripts/
	install -m 644 scripts/reconstruct.py $(PREFIX)/share/oci2bin/scripts/
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
	rm -f $(PREFIX)/bin/oci2bin $(PREFIX)/bin/oci2vm
	rm -rf $(PREFIX)/share/oci2bin
	rm -f $(PREFIX)/share/man/man1/oci2bin.1
	-install-info --delete --dir-file=$(PREFIX)/share/info/dir \
	  $(PREFIX)/share/info/oci2bin.info 2>/dev/null || true
	rm -f $(PREFIX)/share/info/oci2bin.info

clean:
	rm -rf build/loader-* build/test_c_units* build/vmlinux $(OUTPUT)
	rm -f $(INFO_DIR)/oci2bin.info

clean-all: clean
	rm -rf build

# ── Lint targets ───────────────────────────────────────────────────────────────

# Run all linters in sequence.
lint: lint-clang lint-scan-build lint-semgrep

# clang: compile with an extended warning set; -Werror makes CI fail on any hit.
# Flags chosen to catch real bugs without false-positive noise:
#   -Wcast-align          misaligned pointer casts
#   -Wshadow              local variable shadows outer scope
#   -Wstrict-prototypes   missing parameter types in K&R style
#   -Wmissing-prototypes  functions without a prior declaration
#   -Wnull-dereference    paths that provably deref NULL
#   -Wformat=2            strict format-string checking
#   -Wformat-nonliteral   non-literal passed to printf-family
#   -Wimplicit-fallthrough  missing break/fallthrough annotation
#   -Wlogical-op-parentheses  ambiguous && / || mixing
#   -Wunreachable-code    dead code after return/goto/etc
#   -Wcomma               comma operator (often a typo for ';')
#   -Wundef               macro used in #if but never defined
#   -Wduplicate-enum      duplicate enum constant values
CLANG_LINT_FLAGS = -static -O2 -Wall -Wextra -Werror \
                   -Wno-unused-parameter \
                   -Wcast-align \
                   -Wshadow \
                   -Wstrict-prototypes \
                   -Wmissing-prototypes \
                   -Wnull-dereference \
                   -Wformat=2 \
                   -Wformat-nonliteral \
                   -Wimplicit-fallthrough \
                   -Wlogical-op-parentheses \
                   -Wunreachable-code \
                   -Wcomma \
                   -Wundef \
                   -Wduplicate-enum

lint-clang:
	@echo "=== clang lint ($(CC_CLANG)) ==="
	$(CC_CLANG) $(CLANG_LINT_FLAGS) $(VM_DEFS) -o /dev/null src/loader.c
	@echo "clang lint: OK"

# clang static analyzer: interprocedural analysis for null-deref, memory leaks,
# use-after-free, and POSIX API misuse.  The DeprecatedOrUnsafeBufferHandling
# checker is disabled — it flags every snprintf/memcpy as "insecure" because
# the C11 Annex K *_s variants don't exist in glibc.
lint-scan-build:
	@echo "=== clang static analyzer ==="
	$(CC_CLANG) --analyze \
	  -Xanalyzer -analyzer-disable-checker \
	  -Xanalyzer security.insecureAPI.DeprecatedOrUnsafeBufferHandling \
	  -Xanalyzer -analyzer-output=text \
	  $(VM_DEFS) -o /dev/null src/loader.c
	@echo "scan-build: OK"

# semgrep: pattern-based rules covering OWASP top-10 and general C security.
SEMGREP     ?= semgrep
SEMGREP_CONFIGS = --config=p/default --config=p/owasp-top-ten \
                  --config=p/security-audit

lint-semgrep:
	@echo "=== semgrep ==="
	$(SEMGREP) $(SEMGREP_CONFIGS) --error src/loader.c
	@echo "semgrep: OK"

# ── Test targets ──────────────────────────────────────────────────────────────

test: test-unit test-integration

test-unit: test-c test-python test-vm-unit

test-unit-aarch64: test-c-aarch64 test-python

test-c: $(TEST_C_BIN)
	@echo "=== C unit tests (x86_64) ==="
	@$(TEST_C_BIN)

$(TEST_C_BIN): $(TESTS_DIR)/test_c_units.c src/loader.c
	@mkdir -p build $(TEST_TMPDIR)
	$(TEST_ENV) $(CC) -static -Wno-return-local-addr -o $@ $<

test-c-aarch64: $(TEST_C_BIN_AARCH64)
	@echo "=== C unit tests (aarch64 via $(QEMU_AARCH64)) ==="
	@$(QEMU_AARCH64) $(TEST_C_BIN_AARCH64)

$(TEST_C_BIN_AARCH64): $(TESTS_DIR)/test_c_units.c src/loader.c
	@mkdir -p build $(TEST_TMPDIR)
	$(TEST_ENV) $(CC_AARCH64) $(CFLAGS_AARCH64) -static -Wno-return-local-addr -o $@ $<

test-python:
	@echo "=== Python unit tests ==="
	@mkdir -p $(TEST_TMPDIR)
	$(TEST_ENV) python3 -m unittest discover -s tests -p 'test_build.py' -v
	@echo "=== Polyglot structure tests ==="
	$(TEST_ENV) python3 -m unittest tests.test_polyglot.TestExistingPolyglot -v

test-vm-unit:
	@echo "=== VM unit tests ==="
	@mkdir -p $(TEST_TMPDIR)
	$(TEST_ENV) python3 -m unittest tests.test_vm_unit -v

test-vm: test-vm-unit
	@if [ ! -e /dev/kvm ]; then \
	    echo "SKIP: /dev/kvm not available"; exit 0; \
	fi
	$(TEST_ENV) bash tests/test_vm_integration.sh

test-integration: test-integration-redis test-integration-nginx polyglot
	@echo "=== Runtime integration tests ==="
	@mkdir -p $(TEST_TMPDIR)
	@$(TEST_ENV) bash $(TESTS_DIR)/test_runtime.sh
	@echo "=== Build integration tests ==="
	$(TEST_ENV) python3 -m unittest tests.test_polyglot.TestBuildPolyglotIntegration -v

test-integration-redis:
	@echo "=== Redis integration test ==="
	@mkdir -p $(TEST_TMPDIR)
	@$(TEST_ENV) bash $(TESTS_DIR)/test_integration_redis.sh

test-integration-nginx:
	@echo "=== nginx integration test ==="
	@mkdir -p $(TEST_TMPDIR)
	@$(TEST_ENV) bash $(TESTS_DIR)/test_integration_nginx.sh

test-integration-services:
	@echo "=== Service matrix integration tests (container + VM) ==="
	@mkdir -p $(TEST_TMPDIR)
	$(TEST_ENV) python3 -m unittest tests.test_service_matrix -v
