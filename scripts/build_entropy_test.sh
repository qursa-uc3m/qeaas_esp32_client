#!/bin/bash
# ./scripts/build_entropy_test.sh
#
# Copyright (C) 2024-2025 Javier Blanco-Romero @fj-blanco (UC3M, QURSA project)
# Author: Javier Blanco-Romero
#
# Build script for BLAKE2s Entropy Pool Test

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BOARD_TARGET="esp32_devkitc/esp32/procpu"
CLIENT_DIR="$PROJECT_ROOT/mbedtls"

# Defaults
DO_CLEAN=false
DO_INIT=false
DO_FLASH=false
DO_MONITOR=false

usage() {
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  --clean       Clean build directory before building"
    echo "  --init        Initialize west workspace (first time only)"
    echo "  --flash       Flash to ESP32 after successful build"
    echo "  --monitor     Open serial monitor after flash"
    echo "  --all         Do everything: init, clean, build, flash, monitor"
    echo "  -h, --help    Show this help message"
    echo ""
    echo "Examples:"
    echo "  # First time setup and build"
    echo "  $0 --init"
    echo "  $0 --clean"
    echo ""
    echo "  # Build and flash"
    echo "  $0 --flash"
    echo ""
    echo "  # Complete workflow"
    echo "  $0 --all"
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --clean)
            DO_CLEAN=true
            shift
            ;;
        --init)
            DO_INIT=true
            shift
            ;;
        --flash)
            DO_FLASH=true
            shift
            ;;
        --monitor)
            DO_MONITOR=true
            shift
            ;;
        --all)
            DO_CLEAN=true
            DO_FLASH=true
            DO_MONITOR=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

cd "$CLIENT_DIR"

clean_build() {
    echo "Cleaning build directory..."
    rm -rf build/
    find . -name "CMakeCache.txt" -delete 2>/dev/null || true
    find . -name "CMakeFiles" -type d -exec rm -rf {} + 2>/dev/null || true
    echo "✓ Build directory cleaned"
}

init_workspace() {
    echo "Initializing west workspace..."
    echo "Fetching remote Zephyr fork (fj-blanco/zephyr@entropy-pool)"
    west init -l .
    west update
    west blobs fetch hal_espressif 2>/dev/null || true
    echo "✓ Workspace initialized"
}

print_banner() {
    echo ""
    echo "╔════════════════════════════════════════════════╗"
    echo "║  BLAKE2s Entropy Pool Test - Build Script     ║"
    echo "║  Paper: Post-Quantum Entropy as a Service     ║"
    echo "╚════════════════════════════════════════════════╝"
    echo ""
}

print_banner

# Handle init separately (don't build after init)
if [ "$DO_INIT" = true ]; then
    init_workspace
    echo ""
    echo "Workspace initialized successfully!"
    echo "Next steps:"
    echo "  1. Build: $0 --clean"
    echo "  2. Flash: $0 --flash"
    echo "  3. Monitor: west espressif monitor"
    echo ""
    exit 0
fi

# Clean if requested
if [ "$DO_CLEAN" = true ]; then
    clean_build
    echo ""
fi

# Check if workspace is initialized
if [ ! -f ".west/config" ] && [ ! -f "../.west/config" ]; then
    echo "⚠ Workspace not initialized!"
    echo "Please run: $0 --init"
    exit 1
fi

# Update workspace
echo "Updating west modules..."
west update
echo "✓ Modules updated"
echo ""

# Export Zephyr environment
west zephyr-export

echo "Building BLAKE2s Entropy Pool Test..."
echo "Target board: $BOARD_TARGET"
echo "Zephyr source: Local repo (entropy-pool branch)"
echo ""

# Build
west build -p auto -b "$BOARD_TARGET" .

if [ $? -eq 0 ]; then
    echo ""
    echo "╔════════════════════════════════════════════════╗"
    echo "║            ✓ BUILD SUCCESSFUL                  ║"
    echo "╚════════════════════════════════════════════════╝"
    echo ""
    
    # Flash if requested
    if [ "$DO_FLASH" = true ]; then
        echo "Flashing to ESP32..."
        west flash
        
        if [ $? -eq 0 ]; then
            echo "✓ Flash successful"
            
            # Monitor if requested
            if [ "$DO_MONITOR" = true ]; then
                echo ""
                echo "Opening serial monitor..."
                echo "Press Ctrl+] to exit"
                sleep 2
                west espressif monitor
            fi
        else
            echo "✗ Flash failed"
            exit 1
        fi
    else
        echo "Next steps:"
        echo "  Flash:   west flash"
        echo "  Monitor: west espressif monitor"
        echo ""
        echo "Or use: $0 --flash --monitor"
    fi
else
    echo ""
    echo "╔════════════════════════════════════════════════╗"
    echo "║            ✗ BUILD FAILED                      ║"
    echo "╚════════════════════════════════════════════════╝"
    echo ""
    exit 1
fi
