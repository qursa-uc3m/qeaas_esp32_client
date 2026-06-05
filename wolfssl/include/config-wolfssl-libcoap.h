/*
 * config-wolfssl-libcoap.h
 * wolfSSL configuration for libcoap ESP32 client — memory-optimised
 *
 * Supports key-exchange algorithms selected at compile time via
 * COAP_WOLFSSL_GROUPS and signature algorithms via COAP_WOLFSSL_SIG.
 *
 * Key exchange (COAP_WOLFSSL_GROUPS → WOLFSSL_ALGO_*):
 *   "P-256"        → WOLFSSL_ALGO_ECDHE_P256  (default)
 *   "X25519"       → WOLFSSL_ALGO_X25519
 *   "ML_KEM_512"   → WOLFSSL_ALGO_MLKEM512
 *
 * Signature / certificate authentication (COAP_WOLFSSL_SIG → WOLFSSL_SIG_*):
 *   "ECDSA_P256"   → WOLFSSL_SIG_ECDSA_P256  (default)
 *   "ML_DSA_44"    → WOLFSSL_SIG_MLDSA44
 *
 * ML-KEM-768 and ML-KEM-1024 are supported at the build level but crash
 * at runtime on ESP32 due to heap exhaustion during DTLS handshake message
 * reassembly (DtlsMsgCombineFragBuckets → z_realloc exceeds available DRAM).
 *
 * Aggressively tuned for ESP32 DRAM limits (~192 KB total).
 * Every define here was audited for its impact on heap-allocated
 * struct sizes (WOLFSSL, WOLFSSL_CTX) and on per-connection buffers.
 *
 * Copyright (C) 2024-2025 Javier Blanco-Romero @fj-blanco (UC3M, QURSA project)
 */

#ifndef WOLFSSL_SETTINGS_H
#define WOLFSSL_SETTINGS_H

#ifdef __cplusplus
extern "C" {
#endif

#ifndef WOLFSSL_USER_SETTINGS
#define WOLFSSL_USER_SETTINGS
#endif

/* ==================== Algorithm Selection ==================== */

/* --- Key exchange: exactly ONE must be defined --- */
#if !defined(WOLFSSL_ALGO_ECDHE_P256) && !defined(WOLFSSL_ALGO_X25519) && \
    !defined(WOLFSSL_ALGO_MLKEM512)   && !defined(WOLFSSL_ALGO_MLKEM768) && \
    !defined(WOLFSSL_ALGO_MLKEM1024)
#define WOLFSSL_ALGO_ECDHE_P256
#endif

/* --- Signature / certificate authentication --- */
/* Default: ECDSA P-256.  Set WOLFSSL_SIG_MLDSA44 for post-quantum sigs. */
#if !defined(WOLFSSL_SIG_ECDSA_P256) && !defined(WOLFSSL_SIG_MLDSA44)
#define WOLFSSL_SIG_ECDSA_P256
#endif

/* Helper: any ML-KEM variant selected? */
#if defined(WOLFSSL_ALGO_MLKEM512) || defined(WOLFSSL_ALGO_MLKEM768) || \
    defined(WOLFSSL_ALGO_MLKEM1024)
#define _WOLFSSL_ALGO_MLKEM_ANY
#endif

/* Helper: do we need SHA-3 / SHAKE for any PQC algorithm? */
#if defined(_WOLFSSL_ALGO_MLKEM_ANY) || defined(WOLFSSL_SIG_MLDSA44)
#define _WOLFSSL_NEED_SHA3_SHAKE
#endif

/* ==================== Platform ==================== */

#ifndef WOLFSSL_ZEPHYR
#define WOLFSSL_ZEPHYR
#endif

#define NO_STDIO_FILESYSTEM
#define NO_WRITEV
#define NO_DEV_RANDOM
#define HAVE_CUSTOM_RNG
#define NO_MAIN_DRIVER
#define NO_BIO
#define WOLFSSL_NO_STDIO
#define NO_PWDBASED
#define NO_ERROR_QUEUE
#define WOLFSSL_NO_STDIO_PRINTF

/* ==================== TLS / DTLS ==================== */

#define WOLFSSL_DTLS
#define HAVE_SOCKADDR

/* TLS 1.3 — required by DTLS 1.3 (wolfSSL enforces this with #error) */
#define WOLFSSL_TLS13

/* DTLS 1.3 — post-quantum CoAP over DTLS */
#define WOLFSSL_DTLS13

/* WOLFSSL_DTLS_CH_FRAG intentionally NOT defined.
 * The first ClientHello is always small because coap_wolfssl.c calls
 * wolfSSL_NoKeyShares() (gated by WOLFSSL_SEND_HRR_COOKIE), so the
 * ML-KEM key share is never sent in CH1. The server replies with
 * HelloRetryRequest + cookie, and the second ClientHello (with the
 * full ML-KEM key share) uses standard DTLS handshake message
 * fragmentation. This avoids modifying upstream wolfSSL source
 * (dtls13.c CH_FRAG block contains server-only code that fails to
 * compile with NO_WOLFSSL_SERVER).
 * The wolfSSL build will emit a -Wcpp warning about missing CH_FRAG
 * for PQC + DTLS 1.3 — this is benign and expected. */

/* DTLS 1.3 HRR cookie exchange: although WOLFSSL_SEND_HRR_COOKIE sounds
 * server-only, wolfSSL gates ALL cookie extension handling (parse / write /
 * free / get-size) behind this define.  Without it the CLIENT cannot parse
 * the cookie from the server's HelloRetryRequest, so its second
 * ClientHello is identical to the first and the server rejects it with
 * DUPLICATE_MSG_E.  Enabling it also lets coap_wolfssl.c call
 * wolfSSL_NoKeyShares(), the standard DTLS 1.3 cookie flow.
 * Server-only code (CreateCookieExt, DoClientHelloStateless, …) is
 * separately gated by !NO_WOLFSSL_SERVER, so this is safe for the
 * client-only build.
 */
#define WOLFSSL_SEND_HRR_COOKIE

/* --- REMOVED (saves heap per-connection): ---
 * WOLFSSL_DTLS_CID — adds Connection-ID fields to every WOLFSSL struct.
 */

#undef NO_TLS
#undef NO_WOLFSSL_CLIENT

/* Client only — removes server state machine, handshake buffers, etc. */
#define NO_WOLFSSL_SERVER

/* TLS extensions needed by libcoap */
#define HAVE_TLS_EXTENSIONS
#define HAVE_SUPPORTED_CURVES
#define HAVE_SNI   /* wolfSSL_set_tlsext_host_name() used by coap_wolfssl.c */

/* --- REMOVED (not needed, saves struct fields + code): ---
 * HAVE_EXTENDED_MASTER — TLS ≤1.2 feature; DTLS 1.3 doesn't use it.
 */

/* ==================== Key Exchange: X25519 ==================== */

#ifdef WOLFSSL_ALGO_X25519
#define HAVE_CURVE25519
#define CURVE25519_SMALL          /* save DRAM on ESP32 */
#endif

/* ==================== Key Exchange: ML-KEM (FIPS 203) ==================== */

#ifdef _WOLFSSL_ALGO_MLKEM_ANY
/* wolfSSL 5.8.2+ native ML-KEM (no liboqs) */
#define WOLFSSL_HAVE_MLKEM
#define WOLFSSL_WC_MLKEM
/* ── Per-level disable workaround ──
 * Ideally we would define WOLFSSL_NO_ML_KEM_<level> for unneeded levels
 * to save flash/DRAM.  However, wolfSSL 5.8.2 has a bug in
 * TLSX_IsGroupSupported() (tls.c ~line 4580): the switch-case for all
 * three ML-KEM levels shares a single `break;` that lives inside
 * `#ifndef WOLFSSL_NO_ML_KEM_1024`.  When ML-KEM-1024 is compiled out,
 * the ML-KEM-512 / ML-KEM-768 cases fall through without a `break;` and
 * the function returns 0 (not supported).  This causes
 * wolfSSL_CTX_set1_groups_list("ML_KEM_512") to silently fail, the
 * ClientHello omits the group from supported_groups, and the server
 * replies with Alert 109 (missing_extension).
 *
 * Workaround: enable all three levels at compile time.  Only the group
 * passed via COAP_WOLFSSL_GROUPS is actually negotiated at runtime, so
 * the extra code from unused levels costs ~20-30 KB flash but negligible
 * extra DRAM (key material is heap-allocated on demand).
 */
/* ML-KEM small-memory optimisations (from wolfSSL blog Aug 2025).
 * Reduces ML-KEM heap usage by 10-15% by using smaller working buffers
 * for key generation and encapsulation.  No impact on non-PQC builds. */
#define WOLFSSL_MLKEM_ENCAPSULATE_SMALL_MEM
#define WOLFSSL_MLKEM_MAKEKEY_SMALL_MEM
#endif /* _WOLFSSL_ALGO_MLKEM_ANY */

/* ==================== Signature: ML-DSA-44 (FIPS 204) ==================== */

#ifdef WOLFSSL_SIG_MLDSA44
/* wolfSSL 5.8.2+ native ML-DSA (Dilithium) — no liboqs needed */
#define HAVE_DILITHIUM
#define WOLFSSL_WC_DILITHIUM
/* Only compile ML-DSA-44 (Level 2); exclude larger parameter sets */
#define WOLFSSL_NO_ML_DSA_65
#define WOLFSSL_NO_ML_DSA_87
/* Client only verifies server certificates — disable keygen and signing
 * to save substantial code and DRAM */
#define WOLFSSL_DILITHIUM_VERIFY_ONLY
/* Low-memory verification — processes matrix A one row at a time. */
#define WOLFSSL_DILITHIUM_VERIFY_SMALL_MEM
/* Smaller code size (slower, but ESP32 is not time-critical for verify) */
#define WOLFSSL_DILITHIUM_SMALL
/* NOTE: WOLFSSL_DILITHIUM_ASSIGN_KEY cannot be used — the cert DER buffer is
 * freed between cert chain verification and CertificateVerify processing,
 * making the pointer-only public key a stale reference (commit_cmp fails).
 * The full 1312-byte public key copy is required for correct verification. */
#endif /* WOLFSSL_SIG_MLDSA44 */

/* ==================== SHA-3 / SHAKE (shared by ML-KEM and ML-DSA) ==================== */

#ifdef _WOLFSSL_NEED_SHA3_SHAKE
#define WOLFSSL_SHA3
#define WOLFSSL_SHAKE128
#define WOLFSSL_SHAKE256
#endif

/* ==================== Session ==================== */

/* No session resumption needed — each benchmark run creates a fresh session */
#define NO_SESSION_CACHE
#define NO_SESSION_CACHE_REF

/* ==================== Certificates & X.509 (minimal) ==================== */

#undef NO_CERTS
#define WOLFSSL_ASN_TEMPLATE
#define WOLFSSL_DER_LOAD
#define WOLFSSL_PEM_TO_DER
#define WOLFSSL_CERT_VERIFY

/* NO_KEEP_PEER_CERT: prevent OPENSSL_EXTRA from auto-defining KEEP_PEER_CERT
 * in settings.h.  With KEEP_PEER_CERT, ProcessPeerCerts calls
 * CopyDecodedToX509() to populate the embedded ssl->peerCert field.  On
 * ESP32 with ML-DSA-44, this allocation fails (MEMORY_E) at peak heap
 * usage and triggers a fatal handshake abort — requiring a wolfSSL source
 * patch.
 *
 * Without KEEP_PEER_CERT:
 *   - The embedded peerCert field is removed from WOLFSSL, saving ~2 KB
 *     of heap per connection.
 *   - CopyDecodedToX509 is skipped in ProcessPeerCerts entirely.
 *   - If certificate validation succeeds (cert_err == 0), DoVerifyCallback
 *     never calls SetupStoreCtxCallback, so no X509 allocation at all.
 *   - ConfirmSignature (the actual ML-DSA-44 crypto verification) still
 *     runs regardless.
 *
 * This avoids any source-level modification to wolfSSL. */
#define NO_KEEP_PEER_CERT

/* Callback support for libcoap */
#define HAVE_EX_DATA

/* OpenSSL compatibility — required by libcoap's wolfSSL backend.
 * OPENSSL_EXTRA alone covers all 21 functions libcoap needs EXCEPT
 * wolfSSL_CIPHER_get_cipher_nid() and wolfSSL_CIPHER_get_digest_nid()
 * (used in coap_dtls_get_overhead()).  We patch that function to use a
 * fixed overhead for DTLS 1.3 AES-128-GCM instead of importing
 * OPENSSL_ALL which bloats the WOLFSSL struct. */
#define OPENSSL_EXTRA

/* ==================== Crypto algorithms ==================== */

/* Hash — only SHA-256 needed for TLS_AES_128_GCM_SHA256 */
#define WOLFSSL_SHA256
#define HAVE_HKDF
#undef NO_HMAC
/* --- REMOVED: SHA384, SHA512 --- not needed for the single TLS 1.3
 * cipher suite we use.  Saves ~4 KB code and hash-state heap. */

/* ECC — always on for compatibility with wolfSSL's cipher suite requirements.
 * Used for ECDSA certificate authentication and/or ECDHE P-256 key exchange.
 * Even with ML-DSA-44 signatures, ECC is needed by wolfSSL's internal guards. */
#define HAVE_ECC
#define ECC_TIMING_RESISTANT
#define HAVE_ECC_VERIFY
#define HAVE_ECC_SIGN

/* AES — only AES-128-GCM needed for TLS_AES_128_GCM_SHA256 */
#define HAVE_AES
#define HAVE_AESGCM
#define WOLFSSL_AES_128
/* --- REMOVED: AES-256 --- not needed; saves ~2 KB key-schedule tables. */

/* GCM_SMALL — use smaller GCM multiplication table (saves ~3-4 KB DRAM,
 * trades a bit of AES-GCM performance for reduced memory) */
#define GCM_SMALL

/* Smaller AES S-box tables — saves DRAM (256 bytes vs 4 KB) */
#define WOLFSSL_AES_SMALL_TABLES

/* Disable RSA — not used for certificates or key exchange */
#define NO_RSA

/* Disable DH — ML-KEM / ECDHE provide key exchange */
#define NO_DH

/* Random number generation */
#define HAVE_HASHDRBG
#define WC_RNG_SEED_CB

/* ==================== Memory & stack optimisation ==================== */

/* ESP32 has no battery-backed RTC — boots at epoch (1970-01-01).  Skip all
 * ASN.1 date validation so that ParseCertRelative does not return
 * ASN_BEFORE_DATE_E, which would otherwise trigger a fatal alert before
 * the verify callback has a chance to override it. */
#define NO_ASN_TIME

#define WOLFSSL_SMALL_STACK
/* --- REMOVED: WOLFSSL_SMALL_STACK_CACHE --- caches crypto working buffers
 * on the heap, increasing per-connection heap usage.  Without it, wolfSSL
 * allocates from the stack per-operation (covered by WOLFSSL_SMALL_STACK). */

/* ---- I/O buffer size reduction for CoAP over WiFi (MTU ~1500) ----
 * Without these, wolfSSL_connect() dynamically grows the output buffer
 * to OUTPUT_RECORD_SIZE = MAX_RECORD_SIZE = 16384 during handshake,
 * which is the main cause of MEMORY_E (-125) on ESP32.
 *
 * STATIC_CHUNKS_ONLY: caps output buffer to RECORD_SIZE (1400 for DTLS)
 *   instead of 16384.  Handshake messages get fragmented to MTU, which
 *   is exactly what DTLS is designed to do.
 * WOLFSSL_DTLS_MTU: enables MTU-aware I/O sizing and wolfSSL_dtls_set_mtu().
 * WOLFSSL_MAX_MTU: ceiling for DTLS packet size (1400 = 1500 - IP/UDP).
 * WOLFSSL_DTLS_MTU_ADDITIONAL_READ_BUFFER: extra read headroom (default 500,
 *   reduced to 100 since we control the server).
 */
#define STATIC_CHUNKS_ONLY
#define WOLFSSL_DTLS_MTU
#define WOLFSSL_MAX_MTU              1400
#define WOLFSSL_DTLS_MTU_ADDITIONAL_READ_BUFFER  100

#define NO_BENCH
#define WOLFSSL_NO_BENCH

/* Disabled heavyweight features */
#define NO_DSA
#define NO_RC4
#define NO_MD4
#define NO_MD5
#define NO_OLD_TLS

/* Error strings off to save ~10 KB flash + rodata.
 * Diagnostic stage globals in coap_wolfssl.c provide error visibility. */
#define NO_ERROR_STRINGS

/* Math library — SP small for ECC only (no RSA/DH SP needed) */
#define WOLFSSL_SP_MATH_ALL
#define WOLFSSL_SP_SMALL
#define WOLFSSL_HAVE_SP_ECC

/* Threading */
#define SINGLE_THREADED

/* ==================== Memory allocator override ==================== */
/* On Zephyr with newlib, malloc() uses newlib's tiny sbrk-based heap
 * (only ~22 KB from leftover DRAM), while k_malloc() uses the Zephyr
 * system heap sized by CONFIG_HEAP_MEM_POOL_SIZE (80 KB).
 * wolfSSL defaults to malloc() → newlib heap → OOM during handshake.
 *
 * XMALLOC_OVERRIDE tells wolfSSL to skip its default malloc definitions
 * and use our macros instead.  These redirect all wolfSSL allocations
 * to k_malloc/k_free, giving wolfSSL access to the full system heap.
 *
 * Note: k_malloc/k_free are declared in <zephyr/kernel.h> which is
 * included by wolfssl/wolfcrypt/settings.h (WOLFSSL_ZEPHYR block)
 * AFTER this user_settings header.  Macros are text-substituted at
 * point of use, so the declarations are available when XMALLOC expands.
 *
 * CRITICAL: We must NOT use wolfSSL's default z_realloc() for XREALLOC.
 * z_realloc() (wolfcrypt/src/memory.c) calls newlib's realloc(), but
 * XMALLOC/XFREE use Zephyr's k_malloc/k_free.  Passing a k_malloc
 * pointer to newlib's realloc() is an allocator mismatch that crashes
 * in _free_r during DtlsMsgCombineFragBuckets (DTLS fragment
 * reassembly for large ML-DSA-44 certificates).
 * XREALLOC uses Zephyr's k_realloc() which operates on the same
 * system heap as k_malloc/k_free, avoiding the mismatch.
 */
#define XMALLOC_OVERRIDE
#define XMALLOC(s, h, t)     ((void)(h), (void)(t), k_malloc((size_t)(s)))
#define XFREE(p, h, t)       do { void* xp = (p); (void)(h); (void)(t); \
                                if (xp) k_free(xp); } while (0)
#define XREALLOC(p, n, h, t) ((void)(h), (void)(t), k_realloc((p), (size_t)(n)))

/* ==================== Debug ==================== */

#ifdef CONFIG_WOLFSSL_DEBUG
    #ifndef DEBUG_WOLFSSL
        #define DEBUG_WOLFSSL
    #endif
    /* Re-enable error strings when debug is on */
    #undef NO_ERROR_STRINGS
#endif

#ifdef __cplusplus
}
#endif

#endif /* WOLFSSL_SETTINGS_H */