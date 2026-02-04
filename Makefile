# Makefile for entlib-native cross-compilation
# Supports: Linux (.so), Windows (.dll), macOS (.dylib)

LIB_NAME = entlib_native
DIST_DIR = dist

.PHONY: all clean native linux windows macos universal help install-targets

# Default: build for current platform
all: native

help:
	@echo "entlib-native Cross-Compilation Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  make native          - Build for current platform"
	@echo "  make macos           - Build for macOS (x86_64, aarch64)"
	@echo "  make universal       - Build macOS universal binary"
	@echo "  make clean           - Clean build artifacts"
	@echo "  make install-targets - Install all Rust targets"
	@echo ""
	@echo "Docker-based cross-compilation (recommended):"
	@echo "  make docker-all      - Build for all platforms (Linux + Windows)"
	@echo "  make docker-linux    - Build for Linux (x86_64, aarch64)"
	@echo "  make docker-windows  - Build for Windows (x86_64)"
	@echo ""
	@echo "Direct cross-compilation (requires toolchains):"
	@echo "  make linux           - Build for Linux (requires gcc cross-compiler)"
	@echo "  make windows         - Build for Windows (requires MinGW)"
	@echo "  make cross-linux     - Build Linux using 'cross' tool"
	@echo "  make cross-windows   - Build Windows using 'cross' tool"

# Install all cross-compilation targets
install-targets:
	rustup target add x86_64-unknown-linux-gnu
	rustup target add aarch64-unknown-linux-gnu
	rustup target add x86_64-pc-windows-gnu
	rustup target add x86_64-apple-darwin
	rustup target add aarch64-apple-darwin

# Native build
native:
	cargo build --release
	mkdir -p $(DIST_DIR)
	@if [ -f target/release/lib$(LIB_NAME).dylib ]; then \
		cp target/release/lib$(LIB_NAME).dylib $(DIST_DIR)/; \
	elif [ -f target/release/lib$(LIB_NAME).so ]; then \
		cp target/release/lib$(LIB_NAME).so $(DIST_DIR)/; \
	elif [ -f target/release/$(LIB_NAME).dll ]; then \
		cp target/release/$(LIB_NAME).dll $(DIST_DIR)/; \
	fi

# Linux builds
linux: linux-x86_64 linux-aarch64

linux-x86_64:
	mkdir -p $(DIST_DIR)/linux
	cargo build --release --target x86_64-unknown-linux-gnu
	cp target/x86_64-unknown-linux-gnu/release/lib$(LIB_NAME).so $(DIST_DIR)/linux/lib$(LIB_NAME)_x86_64.so

linux-aarch64:
	mkdir -p $(DIST_DIR)/linux
	cargo build --release --target aarch64-unknown-linux-gnu
	cp target/aarch64-unknown-linux-gnu/release/lib$(LIB_NAME).so $(DIST_DIR)/linux/lib$(LIB_NAME)_aarch64.so

# Windows builds
windows: windows-x86_64

windows-x86_64:
	mkdir -p $(DIST_DIR)/windows
	cargo build --release --target x86_64-pc-windows-gnu
	cp target/x86_64-pc-windows-gnu/release/$(LIB_NAME).dll $(DIST_DIR)/windows/$(LIB_NAME)_x86_64.dll

# macOS builds
macos: macos-x86_64 macos-aarch64

macos-x86_64:
	mkdir -p $(DIST_DIR)/macos
	cargo build --release --target x86_64-apple-darwin
	cp target/x86_64-apple-darwin/release/lib$(LIB_NAME).dylib $(DIST_DIR)/macos/lib$(LIB_NAME)_x86_64.dylib

macos-aarch64:
	mkdir -p $(DIST_DIR)/macos
	cargo build --release --target aarch64-apple-darwin
	cp target/aarch64-apple-darwin/release/lib$(LIB_NAME).dylib $(DIST_DIR)/macos/lib$(LIB_NAME)_aarch64.dylib

# macOS universal binary (Intel + Apple Silicon)
universal: macos-x86_64 macos-aarch64
	lipo -create \
		$(DIST_DIR)/macos/lib$(LIB_NAME)_x86_64.dylib \
		$(DIST_DIR)/macos/lib$(LIB_NAME)_aarch64.dylib \
		-output $(DIST_DIR)/macos/lib$(LIB_NAME)_universal.dylib

# Build all platforms
all-platforms: native linux windows macos

# Docker-based cross-compilation (recommended for macOS)
docker-all:
	./scripts/docker-build.sh all

docker-linux:
	./scripts/docker-build.sh linux

docker-windows:
	./scripts/docker-build.sh windows

# Cross tool builds (requires: cargo install cross)
cross-linux:
	mkdir -p $(DIST_DIR)/linux
	cross build --release --target x86_64-unknown-linux-gnu
	cross build --release --target aarch64-unknown-linux-gnu
	cp target/x86_64-unknown-linux-gnu/release/lib$(LIB_NAME).so $(DIST_DIR)/linux/lib$(LIB_NAME)_x86_64.so
	cp target/aarch64-unknown-linux-gnu/release/lib$(LIB_NAME).so $(DIST_DIR)/linux/lib$(LIB_NAME)_aarch64.so

cross-windows:
	mkdir -p $(DIST_DIR)/windows
	cross build --release --target x86_64-pc-windows-gnu
	cp target/x86_64-pc-windows-gnu/release/$(LIB_NAME).dll $(DIST_DIR)/windows/$(LIB_NAME)_x86_64.dll

# Clean
clean:
	cargo clean
	rm -rf $(DIST_DIR)
