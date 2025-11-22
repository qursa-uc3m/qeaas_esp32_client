#!/bin/bash
# ./scripts/build.sh
#
# Copyright (C) 2024-2025 Javier Blanco-Romero @fj-blanco (UC3M, QURSA project)
#
# Build script for QEaaS Entropy Pool + CoAP client

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BOARD_TARGET="esp32_devkitc/esp32/procpu"
CLIENT_DIR="$PROJECT_ROOT/mbedtls"

COAP_IP="134.102.218.18"
COAP_PATH="/hello"
COAP_PORT="5683"
WIFI_SSID=""
WIFI_PASS=""
USE_DTLS=false
DO_CLEAN=false
DO_INIT=false
DO_FLASH=false
DO_MONITOR=false

usage() {
    cat <<EOF
Usage: $0 [options]

Required:
  --wifi-ssid <ssid>    WiFi network name
  --wifi-pass <pass>    WiFi password

Optional:
  --coap-ip <ip>        CoAP server IP (default: 134.102.218.18)
  --coap-path <path>    CoAP server path (default: /hello)
  --coap-port <port>    CoAP server port (default: 5683)
  --use-dtls            Enable DTLS (sets port 5684 if default)
  --clean               Clean build directory first
  --init                Initialize west workspace only
  --flash               Flash after build
  --monitor             Open serial monitor after flash
  -h|--help             Show this help

Example:
  $0 --wifi-ssid "MyWiFi" --wifi-pass "password" --clean --flash --monitor
EOF
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --coap-ip)     COAP_IP="$2"; shift 2 ;;
        --coap-path)   COAP_PATH="$2"; shift 2 ;;
        --coap-port)   COAP_PORT="$2"; shift 2 ;;
        --wifi-ssid)   WIFI_SSID="$2"; shift 2 ;;
        --wifi-pass)   WIFI_PASS="$2"; shift 2 ;;
        --use-dtls)    USE_DTLS=true; shift ;;
        --clean)       DO_CLEAN=true; shift ;;
        --init)        DO_INIT=true; shift ;;
        --flash)       DO_FLASH=true; shift ;;
        --monitor)     DO_MONITOR=true; shift ;;
        -h|--help)     usage; exit 0 ;;
        *)             echo "Unknown: $1"; usage; exit 1 ;;
    esac
done

if [[ -z "$WIFI_SSID" || -z "$WIFI_PASS" ]]; then
    echo "ERROR: --wifi-ssid and --wifi-pass are required"
    usage
    exit 1
fi

cd "$CLIENT_DIR"

clean_build() {
    echo "Cleaning build directory..."
    rm -rf build/
    find . -name "CMakeCache.txt" -delete 2>/dev/null || true
    find . -name "CMakeFiles" -type d -exec rm -rf {} + 2>/dev/null || true
}

install_zephyr_requirements() {
    local zephyr_reqs="$PROJECT_ROOT/zephyr/scripts/requirements.txt"
    if [ -f "$zephyr_reqs" ]; then
        echo "Installing Zephyr requirements..."
        pip install -q -r "$zephyr_reqs"
    else
        echo "WARNING: Zephyr requirements not found at $zephyr_reqs"
    fi
}

init_workspace() {
    echo "Initializing workspace..."
    west init -l .
    west update
    install_zephyr_requirements
    echo "Fetching ESP32 blobs..."
    west blobs fetch hal_espressif
}

if [ "$DO_INIT" = true ]; then
    init_workspace
    echo "Workspace initialized! Run without --init to build."
    exit 0
fi

if [ "$DO_CLEAN" = true ]; then
    clean_build
fi

# Initialize workspace if needed
if [ ! -f ".west/config" ] && [ ! -f "../.west/config" ]; then
    init_workspace
else
    echo "Updating workspace..."
    west update
    echo "Verifying ESP32 blobs..."
    west blobs fetch hal_espressif
fi

west zephyr-export

# Set protocol based on DTLS flag
PROTOCOL="coap"
if [ "$USE_DTLS" = true ]; then
    PROTOCOL="coaps"
    if [ "$COAP_PORT" = "5683" ]; then
        COAP_PORT="5684"
    fi
fi

echo ""
echo "=== Building QEaaS Entropy + CoAP Client ==="
echo "Target: ${PROTOCOL}://${COAP_IP}:${COAP_PORT}${COAP_PATH}"
echo "WiFi: ${WIFI_SSID}"
echo ""

export COAP_IP COAP_PATH COAP_PORT WIFI_SSID WIFI_PASS
if [ "$USE_DTLS" = true ]; then
    export USE_DTLS=1
fi

west build -p auto -b "$BOARD_TARGET" . || { echo "Build FAILED"; exit 1; }

echo ""
echo "Build complete!"

if [ "$DO_FLASH" = true ]; then
    echo "Flashing..."
    west flash || exit 1
fi

if [ "$DO_MONITOR" = true ]; then
    echo "Starting monitor..."
    west espressif monitor
fi

if [ "$DO_FLASH" = false ]; then
    echo ""
    echo "To flash: west flash"
    echo "To monitor: west espressif monitor"
fi