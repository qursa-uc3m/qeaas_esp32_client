#!/bin/bash
#
# Build script for BLAKE2s Entropy Pool Test
# Copyright (C) 2024-2025 Javier Blanco-Romero @fj-blanco (UC3M, QURSA project)
#

set -e

cd "$(dirname "$0")"

echo "╔════════════════════════════════════════════════╗"
echo "║  BLAKE2s Entropy Pool Test - Build Script     ║"
echo "╚════════════════════════════════════════════════╝"
echo ""

# Check if west is initialized
if [ ! -d ".west" ]; then
    echo "⚠ west not initialized. Running west init..."
    west init -l .
    echo "✓ west initialized"
    echo ""
fi

# Update west modules
echo "Updating west modules..."
west update
echo "✓ Modules updated"
echo ""

# Clean previous build
if [ -d "build" ]; then
    echo "Cleaning previous build..."
    rm -rf build
    echo "✓ Build directory cleaned"
    echo ""
fi

# Build
echo "Building for ESP32 DevKitC..."
west build -p -b esp32_devkitc_wroom/esp32/procpu

if [ $? -eq 0 ]; then
    echo ""
    echo "╔════════════════════════════════════════════════╗"
    echo "║            ✓ BUILD SUCCESSFUL                  ║"
    echo "╚════════════════════════════════════════════════╝"
    echo ""
    echo "Next steps:"
    echo "  Flash:   west flash"
    echo "  Monitor: west espressif monitor"
    echo ""
else
    echo ""
    echo "╔════════════════════════════════════════════════╗"
    echo "║            ✗ BUILD FAILED                      ║"
    echo "╚════════════════════════════════════════════════╝"
    echo ""
    exit 1
fi
