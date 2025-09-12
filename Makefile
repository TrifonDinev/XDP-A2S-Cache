# =============================================================================
# Compiler and Linker Settings
# =============================================================================
CC          = clang
CFLAGS      = -O2 -g -MMD -MP
LDFLAGS     = -O2 -lconfig -lelf -lz -lxdp -lbpf
INSTALL     = install
PREFIX      = /usr
ETC_DIR     = /etc/xdpa2scache
BINDIR      = $(PREFIX)/bin
SYSD_DIR    = /etc/systemd/system
OTHER_DIR   = other

# Include paths
INCLUDES = -I/usr/local/include -I/usr/include -I$(LIB_BPF_SRC) -I$(COMMON_DIR)

# XDP (BPF) compiler flags
CFLAGS_BPF = -D__BPF__ -D__BPF_TRACING__ \
             -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types \
             -O2 -c -g -target bpf

# =============================================================================
# Directory Paths
# =============================================================================
BUILD_DIR           = build
BUILD_LOADER_DIR    = $(BUILD_DIR)/loader
BUILD_XDP_DIR       = $(BUILD_DIR)/xdp
SRC_DIR             = src
COMMON_DIR          = $(SRC_DIR)/common
MODULES_DIR         = modules
XDP_TOOLS_DIR       = $(MODULES_DIR)/xdp-tools
LIB_XDP_DIR         = $(XDP_TOOLS_DIR)/lib/libxdp
LIB_BPF_DIR         = $(XDP_TOOLS_DIR)/lib/libbpf
LIB_BPF_SRC         = $(LIB_BPF_DIR)/src

# =============================================================================
# Source and Object Files
# =============================================================================
LOADER_SRC          = loader/loader.c
LOADER_UTILS_SRC    = $(wildcard $(SRC_DIR)/loader/utils/*.c)
LOADER_UTILS_OBJS   = $(patsubst $(SRC_DIR)/loader/utils/%.c, $(BUILD_LOADER_DIR)/%.o, $(LOADER_UTILS_SRC))
LOADER_OBJ          = $(BUILD_LOADER_DIR)/loader.o

XDP_SRC             = xdp/xdp.c
XDP_PROG_OBJ        = xdpa2scache.o
XDP_OUT             = xdpa2scache

LIB_BPF_OBJS        = $(wildcard $(LIB_BPF_SRC)/staticobjs/*.o)
LIB_XDP_OBJS        = $(addprefix $(LIB_XDP_DIR)/sharedobjs/, $(notdir $(wildcard $(LIB_XDP_DIR)/sharedobjs/*.o)))

# =============================================================================
# Include dependencies
# =============================================================================
-include $(LOADER_UTILS_OBJS:.o=.d)
-include $(LOADER_OBJ:.o=.d)
#-include $(XDP_PROG_OBJ:.o=.d)

# =============================================================================
# Targets
# =============================================================================
.PHONY: all clean install libxdp libxdp_clean xdpa2scache_loader xdpa2scache_program

.DEFAULT_GOAL := all

# Build everything
all: xdpa2scache_loader xdpa2scache_program

# =============================================================================
# Loader (User Space) Build
# =============================================================================
# Ensure build dir exists
$(BUILD_LOADER_DIR):
	@mkdir -p $@

$(BUILD_LOADER_DIR)/%.o: $(SRC_DIR)/loader/utils/%.c | $(BUILD_LOADER_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(LOADER_OBJ): $(SRC_DIR)/$(LOADER_SRC) | $(BUILD_LOADER_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

xdpa2scache_loader: libxdp $(LOADER_OBJ) $(LOADER_UTILS_OBJS)
	$(CC) $(LDFLAGS) $(INCLUDES) -o $(BUILD_LOADER_DIR)/$(XDP_OUT) \
	      $(LIB_BPF_OBJS) $(LIB_XDP_OBJS) \
	      $(LOADER_OBJ) $(LOADER_UTILS_OBJS)

# =============================================================================
# XDP (BPF) Program Build
# =============================================================================
$(BUILD_XDP_DIR):
	@mkdir -p $@

xdpa2scache_program: | $(BUILD_XDP_DIR)
	$(CC) $(INCLUDES) $(CFLAGS_BPF) \
	      $(SRC_DIR)/$(XDP_SRC) \
	      -o $(BUILD_XDP_DIR)/$(XDP_PROG_OBJ)

# =============================================================================
# Dependencies (libxdp, libbpf)
# =============================================================================
libxdp:
	$(MAKE) -C $(XDP_TOOLS_DIR) libxdp
	sudo $(MAKE) -C $(LIB_BPF_SRC) install
	sudo $(MAKE) -C $(LIB_XDP_DIR) install

libxdp_clean:
	$(MAKE) -C $(XDP_TOOLS_DIR) clean
	$(MAKE) -C $(LIB_BPF_SRC) clean

# =============================================================================
# Installation
# =============================================================================
install: all
	@mkdir -p $(ETC_DIR)
	$(INSTALL) -m 755 $(BUILD_LOADER_DIR)/$(XDP_OUT) $(BINDIR)/$(XDP_OUT)
	$(INSTALL) -m 644 $(BUILD_XDP_DIR)/$(XDP_PROG_OBJ) $(ETC_DIR)/$(XDP_PROG_OBJ)
	$(INSTALL) -m 644 -D $(OTHER_DIR)/xdpa2scache.service $(SYSD_DIR)/xdpa2scache.service

	@if [ ! -f $(ETC_DIR)/config ]; then \
		$(INSTALL) -m 644 $(OTHER_DIR)/config $(ETC_DIR)/config; \
	fi

# =============================================================================
# Clean
# =============================================================================
clean:
	$(MAKE) -C $(LIB_BPF_SRC) clean
	$(MAKE) -C $(XDP_TOOLS_DIR) clean
	rm -rf $(BUILD_DIR)