#!/bin/bash
# ./scripts/build.sh
#
# Copyright (C) 2024-2025 Javier Blanco-Romero @fj-blanco (UC3M, QURSA project)
# Author: Javier Blanco-Romero
#
# Build script for unified Quantum Entropy as a Service CoAP client

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BOARD_TARGET="esp32_devkitc_wroom/esp32/procpu"
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
    --wifi-ssid <ssid>
    --wifi-pass <pass>
Optional:
    --coap-ip <ip>      (default 134.102.218.18)
    --coap-path <path>  (default /hello)
    --coap-port <port>  (default 5683)
    --use-dtls          (switch to DTLS; sets port 5684 if default)
    --clean             Remove build directory first
    --init              Initialize west workspace
    --flash             Flash after build
    --monitor           Open serial monitor (after flash)
    -h|--help           Show this help
Example:
    $0 --wifi-ssid SSID --wifi-pass PASS --clean --flash --monitor
EOF
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --backend)
            echo "'--backend' ignored (mbedtls fixed)"; shift 2 ;;
        --coap-ip)
            COAP_IP="$2"
            shift 2
            ;;
        --coap-path)
            COAP_PATH="$2"
            shift 2
            ;;
        --coap-port)
            COAP_PORT="$2"
            shift 2
            ;;
        --wifi-ssid)
            WIFI_SSID="$2"
            shift 2
            ;;
        --wifi-pass)
            WIFI_PASS="$2"
            shift 2
            ;;
        --use-dtls)
            USE_DTLS=true
            shift
            ;;
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

if [[ -z "$WIFI_SSID" || -z "$WIFI_PASS" ]]; then echo "Missing WiFi credentials"; usage; exit 1; fi
cd "$CLIENT_DIR"

clean_build() {
    rm -rf build/
    find . -name "CMakeCache.txt" -delete 2>/dev/null || true
    find . -name "CMakeFiles" -type d -exec rm -rf {} + 2>/dev/null || true
}

init_workspace() {
    west init -l .
    west update
    west blobs fetch hal_espressif 2>/dev/null || true
}

if [ "$DO_INIT" = true ]; then init_workspace; exit 0; fi

if [ "$DO_CLEAN" = true ]; then clean_build; fi

# Initialize workspace if needed
if [ ! -f ".west/config" ] && [ ! -f "../.west/config" ]; then init_workspace; else west update; fi

west zephyr-export

# Set protocol based on DTLS flag
PROTOCOL="coap"
if [ "$USE_DTLS" = true ]; then
    PROTOCOL="coaps"
    if [ "$COAP_PORT" = "5683" ]; then
        COAP_PORT="5684"  # Default DTLS port
    fi
fi

echo "Build: CoAP entropy client -> ${PROTOCOL}://${COAP_IP}:${COAP_PORT}${COAP_PATH}"

# Export environment variables for CMake
export COAP_IP COAP_PATH COAP_PORT WIFI_SSID WIFI_PASS
if [ "$USE_DTLS" = true ]; then
    export USE_DTLS=1
fi

west build -p auto -b "$BOARD_TARGET" . || { echo "Build failed"; exit 1; }
if [ "$DO_FLASH" = true ]; then west flash || exit 1; fi
if [ "$DO_MONITOR" = true ]; then west espressif monitor; fi