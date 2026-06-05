#
# wolfssl/CMakeLists.txt
#
# Copyright (C) 2024-2025 Javier Blanco-Romero @fj-blanco (UC3M, QURSA project)
#
# CMake configuration for CoAP client with wolfSSL
#

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(libcoap_wolfssl_client)

# CoAP server configuration
set(COAP_SERVER_IP_VALUE $ENV{COAP_IP})
set(COAP_SERVER_PATH_VALUE $ENV{COAP_PATH})
set(COAP_SERVER_PORT_VALUE $ENV{COAP_PORT})

if(DEFINED COAP_IP)
    set(COAP_SERVER_IP_VALUE ${COAP_IP})
endif()

if(DEFINED COAP_PATH)
    set(COAP_SERVER_PATH_VALUE ${COAP_PATH})
endif()

if(DEFINED COAP_PORT)
    set(COAP_SERVER_PORT_VALUE ${COAP_PORT})
endif()

if(NOT COAP_SERVER_IP_VALUE)
    set(COAP_SERVER_IP_VALUE "134.102.218.18")
endif()

if(NOT COAP_SERVER_PATH_VALUE)
    set(COAP_SERVER_PATH_VALUE "/hello")
endif()

if(NOT COAP_SERVER_PORT_VALUE)
    set(COAP_SERVER_PORT_VALUE "5683")
endif()

# DTLS configuration
set(USE_DTLS_VALUE $ENV{USE_DTLS})
if(DEFINED USE_DTLS)
    set(USE_DTLS_VALUE ${USE_DTLS})
endif()

# COAP_WOLFSSL_GROUPS — colon-separated TLS 1.3 named groups for libcoap.
# Same mechanism used on the server side (install_libcoap.sh).
# Examples: "P-256", "X25519", "ML_KEM_512", "P-256:ML_KEM_768"
# On ESP32 only ONE ML-KEM level fits in DRAM; specify a single group per build.
set(COAP_WOLFSSL_GROUPS_VALUE $ENV{COAP_WOLFSSL_GROUPS})
if(DEFINED COAP_WOLFSSL_GROUPS)
    set(COAP_WOLFSSL_GROUPS_VALUE ${COAP_WOLFSSL_GROUPS})
endif()

# COAP_WOLFSSL_SIG — signature algorithm for certificate authentication.
# Examples: "ECDSA_P256" (default), "ML_DSA_44"
set(COAP_WOLFSSL_SIG_VALUE $ENV{COAP_WOLFSSL_SIG})
if(DEFINED COAP_WOLFSSL_SIG)
    set(COAP_WOLFSSL_SIG_VALUE ${COAP_WOLFSSL_SIG})
endif()

# Handle WiFi configuration
set(WIFI_SSID_VALUE $ENV{WIFI_SSID})
set(WIFI_PASS_VALUE $ENV{WIFI_PASS})

if(DEFINED WIFI_SSID)
    set(WIFI_SSID_VALUE ${WIFI_SSID})
endif()

if(DEFINED WIFI_PASS)
    set(WIFI_PASS_VALUE ${WIFI_PASS})
endif()

if(NOT WIFI_SSID_VALUE)
    set(WIFI_SSID_VALUE "WIFI_SSID_NOT_SET")
endif()

if(NOT WIFI_PASS_VALUE)
    set(WIFI_PASS_VALUE "WIFI_PASS_NOT_SET")
endif()

zephyr_include_directories(include)

target_include_directories(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_sources(app PRIVATE src/main.c src/wifi.c)
target_link_libraries(app PRIVATE coap-3)

target_compile_definitions(app PRIVATE
    COAP_SERVER_IP="${COAP_SERVER_IP_VALUE}"
    COAP_SERVER_PATH="${COAP_SERVER_PATH_VALUE}"
    COAP_SERVER_PORT=${COAP_SERVER_PORT_VALUE}
    WIFI_SSID="${WIFI_SSID_VALUE}"
    WIFI_PASS="${WIFI_PASS_VALUE}"
)

# Add DTLS support if enabled
if(USE_DTLS_VALUE)
    target_compile_definitions(app PRIVATE USE_DTLS=1)
    message(STATUS "DTLS mode: ENABLED")
else()
    message(STATUS "DTLS mode: DISABLED")
endif()

# ── COAP_WOLFSSL_GROUPS → libcoap + wolfSSL config ──────────────
# Pass the groups string to libcoap so coap_wolfssl.c calls
# wolfSSL_CTX_set1_groups_list() with these groups at runtime.
# Also derive the WOLFSSL_ALGO_* define that the parametric
# config-wolfssl-libcoap.h uses to enable only the needed crypto
# (critical for ESP32 DRAM budget).
if(COAP_WOLFSSL_GROUPS_VALUE)
    target_compile_definitions(coap-3 PRIVATE
        COAP_WOLFSSL_GROUPS="${COAP_WOLFSSL_GROUPS_VALUE}")
endif()

# ── Pre-define cipher lists to eliminate 3×4096-byte static buffers ──
# coap_wolfssl.c allocates psk_ciphers[4096], pki_ciphers[4096], and
# ciphers[4096] when these macros are NOT defined.  Pre-defining them
# turns each into a tiny initialized string → saves ~12 KB DRAM.
# For TLS 1.3 (DTLS 1.3) we only use AES-128-GCM-SHA256.
target_compile_definitions(coap-3 PRIVATE
    COAP_WOLFSSL_PKI_CIPHERS="TLS13-AES128-GCM-SHA256"
    COAP_WOLFSSL_PSK_CIPHERS="TLS13-AES128-GCM-SHA256"
)

if(COAP_WOLFSSL_GROUPS_VALUE)

    # Map groups string → wolfSSL config header switch.
    # Only the first ML-KEM level found wins (ESP32 fits one at a time).
    if(COAP_WOLFSSL_GROUPS_VALUE MATCHES "ML_KEM_1024")
        set(_WOLFSSL_ALGO "MLKEM1024")
    elseif(COAP_WOLFSSL_GROUPS_VALUE MATCHES "ML_KEM_768")
        set(_WOLFSSL_ALGO "MLKEM768")
    elseif(COAP_WOLFSSL_GROUPS_VALUE MATCHES "ML_KEM_512")
        set(_WOLFSSL_ALGO "MLKEM512")
    elseif(COAP_WOLFSSL_GROUPS_VALUE MATCHES "X25519")
        set(_WOLFSSL_ALGO "X25519")
    else()
        set(_WOLFSSL_ALGO "ECDHE_P256")
    endif()
else()
    set(_WOLFSSL_ALGO "ECDHE_P256")
endif()

# Use zephyr_compile_definitions so the algo define is visible to ALL targets
# (app, wolfSSL module, libcoap).  This is critical for non-P-256 algorithms
# because config-wolfssl-libcoap.h gates crypto enablement via these defines,
# and the header is compiled as part of the wolfSSL Zephyr module.
zephyr_compile_definitions(WOLFSSL_ALGO_${_WOLFSSL_ALGO}=1)

# ── COAP_WOLFSSL_SIG → signature algorithm selection ──────────────
# Maps the signature algorithm string to WOLFSSL_SIG_* defines.
if(COAP_WOLFSSL_SIG_VALUE MATCHES "ML_DSA_44")
    set(_WOLFSSL_SIG "MLDSA44")
else()
    set(_WOLFSSL_SIG "ECDSA_P256")
endif()

zephyr_compile_definitions(WOLFSSL_SIG_${_WOLFSSL_SIG}=1)

# Raise DTLS MTU from the libcoap default of 1152 to ~Ethernet/WiFi max.
# Fewer DTLS fragments = fewer lost packets = faster PQ handshakes.
zephyr_compile_definitions(COAP_DEFAULT_MTU=1400)

# Halve the DTLS retransmission base timer (default 1000 ms) so the first
# retry fires sooner after a lost fragment.  Combined with a higher
# max_retransmit (set at runtime), this gives PQ handshakes many more
# chances within the 30 s application timeout.
zephyr_compile_definitions(COAP_DTLS_RETRANSMIT_MS=500)

# ── SKIP_PEER_VERIFY → disable DTLS certificate verification ─────
# When set, the client accepts any server certificate without checking
# the CA chain.  Useful for lab/benchmarking with self-signed certs.
if(DEFINED ENV{SKIP_PEER_VERIFY})
    target_compile_definitions(app PRIVATE SKIP_PEER_VERIFY=1)
    set(_VERIFY_PEER "OFF")
else()
    set(_VERIFY_PEER "ON")
endif()

message(STATUS "...............................................")
message(STATUS "ZEPHYR_EXTRA_MODULES after Zephyr package: ${ZEPHYR_EXTRA_MODULES}")
message(STATUS "wolfSSL configuration enabled")
message(STATUS "COAP_WOLFSSL_GROUPS: ${COAP_WOLFSSL_GROUPS_VALUE}")
message(STATUS "wolfSSL key exchange: ${_WOLFSSL_ALGO}")
message(STATUS "wolfSSL signature:    ${_WOLFSSL_SIG}")
message(STATUS "Verify peer cert:     ${_VERIFY_PEER}")
message(STATUS "CoAP Server: ${COAP_SERVER_IP_VALUE}${COAP_SERVER_PATH_VALUE}:${COAP_SERVER_PORT_VALUE}")
message(STATUS "WiFi Network: ${WIFI_SSID_VALUE}")
message(STATUS "...............................................")