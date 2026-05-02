# =============================================================================
# Project Metadata & Toolchain
# =============================================================================
PROJ        := xdpa2scache
CONFIG_FILE := config
CC          := clang
INSTALL     ?= install

# Robust toolchain metadata extraction
CLANG_VER   := $(shell $(CC) --version | head -n 1)

# Terminal Colors
CYAN        := \033[0;36m
GREEN       := \033[0;32m
YELLOW      := \033[0;33m
RED         := \033[0;31m
NC          := \033[0m

# =============================================================================
# Static / System Libraries
# =============================================================================
# 0 = Use local submodule static build
# 1 = Use system installed libraries (libxdp-dev, libbpf-dev)
USE_SYSTEM_LIBS := 1

# =============================================================================
# Installation Paths
# =============================================================================
PREFIX   ?= /usr
BINDIR   := $(DESTDIR)$(PREFIX)/bin
SYSD_DIR := $(DESTDIR)$(PREFIX)/lib/systemd/system
ETC_DIR  := $(DESTDIR)/etc/$(PROJ)

# =============================================================================
# Directories & Flags
# =============================================================================
SRC_DIR   := src
BUILD_DIR := build
MOD_ROOT  := modules/xdp-tools
LIB_ROOT  := $(MOD_ROOT)/lib

INCLUDES  := -I$(LIB_ROOT)/libbpf/src \
             -I$(SRC_DIR)/common \
             -I$(SRC_DIR)/loader/utils \
             -I$(SRC_DIR)/xdp/utils

CFLAGS    := -O2 -g -MMD -MP -pthread $(INCLUDES)

CFLAGS_BPF := -O2 -g -target bpf -MMD -MP $(INCLUDES) \
              -Wno-unused-value \
              -Wno-pointer-sign \
              -Wno-compare-distinct-pointer-types

# Base Linker flags
BASE_LDFLAGS := -lconfig -lelf -lz -pthread

ifeq ($(USE_SYSTEM_LIBS),1)
	MODE_STR       := System libraries (USE_SYSTEM_LIBS 1)
	LDFLAGS        := -lxdp -lbpf $(BASE_LDFLAGS)
	LIB_DEPS       :=
	GET_STATIC_OBJS :=
else
	MODE_STR       := Static submodule (USE_SYSTEM_LIBS 0)
	LDFLAGS        := $(BASE_LDFLAGS)
	LIB_DEPS       := $(LIB_ROOT)/libxdp/libxdp.a
	GET_STATIC_OBJS := $(wildcard $(LIB_ROOT)/libbpf/src/staticobjs/*.o) \
	                  $(wildcard $(LIB_ROOT)/libxdp/sharedobjs/*.o)
endif

# =============================================================================
# Safety Checks
# =============================================================================
ifeq ($(wildcard $(MOD_ROOT)/Makefile),)
$(error [ERROR] Missing submodule $(MOD_ROOT). Run: git submodule update --init or download submodules manually)
endif

ifeq ($(USE_SYSTEM_LIBS),1)
	SKIP_CHECK := install-deps uninstall-deps uninstall clean

	ifeq ($(filter $(SKIP_CHECK),$(MAKECMDGOALS)),)
		LIB_CHECK := $(shell ld -lxdp -lbpf -o /dev/null 2>/dev/null && echo ok || echo fail)

		ifeq ($(LIB_CHECK),fail)
$(error [ERROR] System libraries (libxdp/libbpf) missing! To fix: Run 'make install-deps')
		endif
	endif
endif

# =============================================================================
# Sources & Objects Discovery
# =============================================================================
LOADER_SRCS := $(SRC_DIR)/loader/loader.c \
               $(wildcard $(SRC_DIR)/loader/utils/*.c)

LOADER_OBJS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(LOADER_SRCS))

XDP_OBJS    := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o, \
               $(wildcard $(SRC_DIR)/xdp/*.c))

TARGET  := $(BUILD_DIR)/$(PROJ)
XDP_OUT := $(BUILD_DIR)/xdp/xdp.o

# =============================================================================
# Main Targets
# =============================================================================
.PHONY: all print_info deps install-deps install uninstall clean

.DEFAULT_GOAL := all

all: print_info deps $(TARGET) $(XDP_OBJS)
	@echo "$(GREEN)[OK] Build complete for $(PROJ)$(NC)"

print_info:
	@echo "$(CYAN)======================================================$(NC)"
	@echo "$(CYAN) Building Project: $(PROJ)$(NC)"
	@echo "$(CYAN) Mode:             $(MODE_STR)$(NC)"
	@echo "$(CYAN) Compiler:         $(CLANG_VER)$(NC)"
	@echo "$(CYAN)======================================================$(NC)"

# Linking Rule
$(TARGET): $(LOADER_OBJS) $(LIB_DEPS)
	@mkdir -p $(@D)
	@echo "  [LD]    $(notdir $@)"
	@$(CC) $(LOADER_OBJS) $(GET_STATIC_OBJS) -o $@ $(LDFLAGS)

# User space compilation
$(BUILD_DIR)/loader/%.o: $(SRC_DIR)/loader/%.c Makefile
	@mkdir -p $(@D)
	@echo "  [CC]    $<"
	@$(CC) $(CFLAGS) -c $< -o $@

# XDP Kernel program compilation
$(BUILD_DIR)/xdp/%.o: $(SRC_DIR)/xdp/%.c Makefile
	@mkdir -p $(@D)
	@echo "  [XDP]   $<"
	@$(CC) $(CFLAGS_BPF) -c $< -o $@

# =============================================================================
# Submodule Management
# =============================================================================
deps:
ifeq ($(USE_SYSTEM_LIBS),0)
	@if [ ! -f $(LIB_ROOT)/libxdp/libxdp.a ]; then \
		echo "$(CYAN)[BUILD] Compiling local dependencies (xdp-tools)...$(NC)"; \
		$(MAKE) -C $(MOD_ROOT) libxdp \
			EXTRA_CFLAGS="-Wno-discarded-qualifiers -Wno-incompatible-pointer-types" \
			WERROR_FLAGS="" > /dev/null || { echo "$(RED)[ERROR] Build failed!$(NC)"; exit 1; }; \
	fi
endif

install-deps:
	@echo "$(CYAN)[INSTALL] Deploying libxdp and libbpf to system...$(NC)"
	@echo "$(CYAN)[BUILD] Building dependencies with compatibility flags... Please wait...$(NC)"
	@$(MAKE) -C $(MOD_ROOT) libxdp \
		EXTRA_CFLAGS="-Wno-discarded-qualifiers -Wno-incompatible-pointer-types" \
		WERROR_FLAGS="" > /dev/null

	@sudo $(MAKE) -C $(LIB_ROOT)/libxdp install
	@sudo $(MAKE) -C $(LIB_ROOT)/libbpf/src install

	@LIB_P=$$(find /usr/local/lib* /usr/lib64 /usr/lib/x86_64-linux-gnu \
		-name "libbpf.so.1" -exec dirname {} \; | sort -u | head -n 1); \
	if [ -n "$$LIB_P" ]; then \
		echo "$$LIB_P" | sudo tee /etc/ld.so.conf.d/xdp-libs.conf > /dev/null; \
	fi

	@sudo ldconfig
	@echo "$(GREEN)[OK] System libraries installed and linker cache updated.$(NC)"

uninstall-deps:
	@echo "$(YELLOW)======================================================$(NC)"
	@echo "$(RED)WARNING: SYSTEM LIBRARY DELETION$(NC)"
	@echo "$(YELLOW)======================================================$(NC)"
	@echo "This command will search for and DELETE libxdp and libbpf from system paths."
	@echo "It will ignore libraries managed by apt/dpkg."

	@printf "$(CYAN)Are you sure you want to proceed? [y/N]: $(NC)" && read ans < /dev/tty; \
	if [ "$$ans" != "y" ] && [ "$$ans" != "Y" ]; then \
		echo "$(RED)Uninstall cancelled.$(NC)"; \
		exit 1; \
	fi

	@echo "$(RED)[UNINSTALL] Dynamically locating and removing manual installs...$(NC)"

	@for lib in xdp bpf; do \
		LIB_FILE=$$(ldconfig -p | grep "lib$$lib.so" | head -n 1 | awk '{print $$NF}'); \
		if [ -z "$$LIB_FILE" ]; then \
			LIB_FILE=$$(find /usr/local/lib /usr/lib /lib /usr/lib64 /lib64 \
				/usr/lib/x86_64-linux-gnu -name "lib$$lib.[as]*" 2>/dev/null | head -n 1); \
		fi; \
		if [ -n "$$LIB_FILE" ] && [ -f "$$LIB_FILE" ]; then \
			if ! dpkg -S "$$LIB_FILE" >/dev/null 2>&1; then \
				LIB_DIR=$$(dirname "$$LIB_FILE"); \
				echo "$(RED)  [RM] lib$$lib found at: $$LIB_DIR$(NC)"; \
				sudo rm -f $$LIB_DIR/lib$$lib.so*; \
				sudo rm -f $$LIB_DIR/lib$$lib.a; \
				sudo rm -f $$LIB_DIR/pkgconfig/lib$$lib.pc 2>/dev/null; \
				sudo rm -rf /usr/include/$$lib /usr/local/include/$$lib \
					/usr/include/xdp /usr/local/include/xdp \
					/usr/include/bpf /usr/local/include/bpf 2>/dev/null; \
			else \
				echo "$(YELLOW)  [SKIP] lib$$lib is managed by system package manager.$(NC)"; \
			fi; \
		else \
			echo "  [INFO] lib$$lib not found in system paths."; \
		fi; \
	done

	@sudo rm -f /etc/ld.so.conf.d/xdp-libs.conf

	@if [ -f $(MOD_ROOT)/Makefile ]; then \
		echo "$(RED)[CLEAN] Cleaning local submodule build artifacts...$(NC)"; \
		$(MAKE) -C $(MOD_ROOT) distclean > /dev/null 2>&1 || true; \
	fi

	@sudo ldconfig
	@echo "$(GREEN)[OK] Uninstall-deps finished successfully.$(NC)"

# =============================================================================
# Install & Uninstall
# =============================================================================
install: all
	@echo "$(CYAN)[INSTALL] Deploying $(PROJ) to $(if $(DESTDIR),$(DESTDIR),system root (/))...$(NC)"

	@mkdir -p $(BINDIR) $(ETC_DIR) $(SYSD_DIR)

	@echo "  [COPY]  Binary -> $(BINDIR)"
	@$(INSTALL) -C -m 755 $(TARGET) $(BINDIR)/$(PROJ)

	@echo "  [COPY]  XDP Object -> $(ETC_DIR)"
	@$(INSTALL) -C -m 644 $(XDP_OUT) $(ETC_DIR)/$(PROJ).o

	@if [ ! -f $(ETC_DIR)/$(CONFIG_FILE) ]; then \
		echo "  [CONF]  Installing default config..."; \
		$(INSTALL) -m 644 other/$(CONFIG_FILE) $(ETC_DIR)/; \
	fi

	@if ! cmp -s other/$(PROJ).service $(SYSD_DIR)/$(PROJ).service; then \
		echo "  [SYSD]  Updating service file and reloading daemon..."; \
		$(INSTALL) -m 644 other/$(PROJ).service $(SYSD_DIR)/; \
		if [ -z "$(DESTDIR)" ]; then systemctl daemon-reload; fi; \
	fi

	@echo "$(GREEN)[OK] Installation is up to date$(NC)"

uninstall:
	@echo "$(YELLOW)======================================================$(NC)"
	@echo "$(RED)WARNING: REMOVING $(PROJ)$(NC)"
	@echo "$(YELLOW)======================================================$(NC)"
	@echo "This command will stop the service and remove $(PROJ) from the system."
	@echo "Files to be deleted:"
	@echo "  - Binary: $(BINDIR)/$(PROJ)"
	@echo "  - Service: $(SYSD_DIR)/$(PROJ).service"
	@echo "  - Configs: $(ETC_DIR) (ALL DATA WILL BE LOST)"

	@printf "\n$(CYAN)Are you sure you want to proceed? [y/N]: $(NC)" && read ans < /dev/tty; \
	if [ "$$ans" != "y" ] && [ "$$ans" != "Y" ]; then \
		echo "$(RED)Uninstall cancelled.$(NC)"; \
		exit 1; \
	fi

	@echo "$(RED)[UNINSTALL] Removing $(PROJ)...$(NC)"
	@if [ -z "$(DESTDIR)" ]; then \
		echo "  [SYSD] Stopping and disabling service..."; \
		sudo systemctl stop $(PROJ).service 2>/dev/null || true; \
		sudo systemctl disable $(PROJ).service 2>/dev/null || true; \
	fi

	@echo "  [RM]   Removing files..."
	sudo rm -f $(BINDIR)/$(PROJ) $(SYSD_DIR)/$(PROJ).service
	sudo rm -rf $(ETC_DIR)

	@if [ -z "$(DESTDIR)" ]; then \
		echo "  [SYSD] Reloading daemon..."; \
		sudo systemctl daemon-reload; \
	fi

	@echo "$(GREEN)[OK] Uninstall complete$(NC)"

# =============================================================================
# Cleanup
# =============================================================================
clean:
	@echo "$(RED)[CLEAN] Removing build directory...$(NC)"
	rm -rf $(BUILD_DIR)

# =============================================================================
# Dependency tracking
# =============================================================================
-include $(LOADER_OBJS:.o=.d) $(XDP_OBJS:.o=.d)