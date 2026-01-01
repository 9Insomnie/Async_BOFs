# Makefile for Async BOF Implant Components
# Author: Offensive Security Researcher
# Date: 2025
#
# This Makefile compiles the implant-side components of the Async BOF framework.
# These components are integrated into the beacon/implant binary.

# ============================================================================
# CONFIGURATION
# ============================================================================

# Compiler selection
# For Windows: use MinGW-w64 or MSVC
# For Linux Cross-compile: use x86_64-w64-mingw32-gcc
CC ?= gcc
WINDRES ?= windres

# Compiler flags
CFLAGS = -Wall -Wextra -O2 -fPIC -DUNICODE -D_UNICODE
CFLAGS += -DBUILDING_ASYNC_BOF

# Debug build (uncomment for debug version)
# CFLAGS += -g -DDEBUG_ASYNC_BOF -DDEBUG

# Release build (stripped symbols)
# CFLAGS += -s

# Linker flags
LDFLAGS = -shared -lkernel32 -lntdll -static-libgcc

# Directories
SRC_DIR = src
INCLUDE_DIR = include
BUILD_DIR = build
OBJ_DIR = $(BUILD_DIR)/obj
EXAMPLES_DIR = examples

# Object files
IMPLANT_OBJ = $(OBJ_DIR)/async_bof_implant.o
COFF_PATCH_OBJ = $(OBJ_DIR)/coff_patch.o
OPSEC_OBJ = $(OBJ_DIR)/opsec_optimizations.o

# Output files
ASYNC_BOF_LIB = $(BUILD_DIR)/async_bof.lib
ASYNC_BOF_DLL = $(BUILD_DIR)/async_bof.dll

# ============================================================================
# TARGETS
# ============================================================================

.PHONY: all clean directories lib dll examples install

# Default target: build library
all: directories lib

# Create build directories
directories:
	@mkdir -p $(OBJ_DIR)
	@mkdir -p $(BUILD_DIR)
	@mkdir -p $(BUILD_DIR)/examples
	@echo "Build directories created"

# Build static library (for linking into beacon)
lib: directories $(ASYNC_BOF_LIB)
	@echo ""
	@echo "=========================================="
	@echo "Async BOF Library built successfully!"
	@echo "Library: $(ASYNC_BOF_LIB)"
	@echo "=========================================="
	@echo ""

# Build DLL (for testing/dynamic loading)
dll: directories $(ASYNC_BOF_DLL)
	@echo ""
	@echo "=========================================="
	@echo "Async BOF DLL built successfully!"
	@echo "DLL: $(ASYNC_BOF_DLL)"
	@echo "=========================================="
	@echo ""

# Build example BOFs
examples: all
	@echo "Building example BOFs..."
	@$(MAKE) -C $(EXAMPLES_DIR) -f Makefile.bof

# Static library target
$(ASYNC_BOF_LIB): $(IMPLANT_OBJ) $(COFF_PATCH_OBJ) $(OPSEC_OBJ)
	@echo "Archiving static library..."
	ar rcs $@ $^
	@echo "Library archived: $(ASYNC_BOF_LIB)"

# DLL target
$(ASYNC_BOF_DLL): $(IMPLANT_OBJ) $(COFF_PATCH_OBJ) $(OPSEC_OBJ)
	@echo "Linking DLL..."
	$(CC) $(LDFLAGS) -o $@ $^
	@echo "DLL linked: $(ASYNC_BOF_DLL)"

# Compile source files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@echo "Compiling: $<"
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) -c $< -o $@

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR)
	@$(MAKE) -C $(EXAMPLES_DIR) -f Makefile.bof clean 2>/dev/null || true
	@echo "Clean complete"

# Install to beacon directory (customize this path)
install: all
	@echo "Installing Async BOF components..."
	@echo "NOTE: Update the installation paths in this Makefile"
	@mkdir -p /usr/local/include/async_bof
	@cp $(INCLUDE_DIR)/async_bof.h /usr/local/include/async_bof/
	@cp $(INCLUDE_DIR)/async_bof_implant.h /usr/local/include/async_bof/
	@cp $(ASYNC_BOF_LIB) /usr/local/lib/
	@echo "Installation complete"
	@echo "Headers: /usr/local/include/async_bof/"
	@echo "Library: /usr/local/lib/$(notdir $(ASYNC_BOF_LIB))"

# ============================================================================
# SPECIAL TARGETS
# ============================================================================

# Generate documentation (requires doxygen)
docs:
	@echo "Generating documentation..."
	@doxygen Doxyfile 2>/dev/null || echo "Doxygen not configured"

# Run static analysis (requires cppcheck)
analyze:
	@echo "Running static analysis..."
	@cppcheck --enable=all --std=c11 -I$(INCLUDE_DIR) $(SRC_DIR)/

# Format source code (requires clang-format)
format:
	@echo "Formatting source code..."
	@clang-format -i $(SRC_DIR)/*.c $(INCLUDE_DIR)/*.h

# Show help
help:
	@echo "Async BOF Framework - Build System"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  all        - Build static library (default)"
	@echo "  lib        - Build static library for linking"
	@echo "  dll        - Build DLL for testing"
	@echo "  examples   - Build example BOFs"
	@echo "  clean      - Remove build artifacts"
	@echo "  install    - Install to system (requires sudo)"
	@echo "  docs       - Generate documentation"
	@echo "  analyze    - Run static analysis"
	@echo "  format     - Format source code"
	@echo "  help       - Show this help message"
	@echo ""
	@echo "Examples:"
	@echo "  make              # Build library"
	@echo "  make dll          # Build test DLL"
	@echo "  make examples     # Build example BOFs"
	@echo "  make clean        # Clean build"
	@echo ""
	@echo "Configuration:"
	@echo "  CC=$(CC)"
	@echo "  CFLAGS=$(CFLAGS)"
	@echo ""
