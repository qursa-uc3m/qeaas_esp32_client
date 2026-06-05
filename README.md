# QEaaS ESP32 Client

Quantum Entropy as a Service (QEaaS) client and entropy-pool validation
applications for ESP32 using Zephyr RTOS.

The wolfSSL application retrieves quantum entropy over CoAP/DTLS and mixes it
with local hardware entropy in the custom BLAKE2s entropy pool. It supports
P-256, X25519, ML-KEM key exchange, ECDSA P-256 authentication, and ML-DSA-44
authentication.

## Companion Publications

This repository accompanies *Post-Quantum Entropy as a Service for Embedded
Systems*: the UCAmI 2025 workshop paper, its extended
[arXiv preprint](https://arxiv.org/abs/2603.10274), and the published extended
article in *Sensors*, **26**(9), 2737 (2026).

## Applications

- `wolfssl/`: CoAP/DTLS QEaaS client using wolfSSL.
- `mbedtls/`: BLAKE2s entropy-pool validation application from the development
  repository.

Both applications use the Zephyr fork declared in their `west.yml` manifests.

## Environment

```bash
conda create -n qeaas_esp32_client python=3.12 -y
conda activate qeaas_esp32_client
pip install -r requirements.txt
```

WiFi credentials can be passed on the command line or loaded from `.env`:

```bash
cp .env.example .env
```

## wolfSSL Client

Initialize the workspace:

```bash
./scripts/build.sh --backend wolfssl --init
```

Build, flash, and monitor a plain CoAP client:

```bash
./scripts/build.sh --backend wolfssl --wifi-ssid SSID --wifi-pass PASS \
  --clean --flash --monitor
```

Build a DTLS client using ECDHE P-256 and ECDSA:

```bash
./scripts/build.sh --backend wolfssl --use-dtls --groups P-256 \
  --wifi-ssid SSID --wifi-pass PASS --clean --flash --monitor
```

Build a DTLS client using ML-KEM-512 and ML-DSA-44:

```bash
./scripts/build.sh --backend wolfssl --use-dtls --groups ML_KEM_512 \
  --sig ML_DSA_44 --wifi-ssid SSID --wifi-pass PASS --clean --flash --monitor
```

For certificate verification, clone the QEaaS server into the repository root:

```bash
git clone https://github.com/qursa-uc3m/qeaas-server.git
```

The build runs `scripts/generate_ca_header.sh` to embed the available ECDSA and
ML-DSA CA certificates. Use `--no-verify` for a build that skips peer
certificate verification.

## Entropy-Pool Validation

Initialize and build the validation application:

```bash
./scripts/build_entropy_test.sh --init
./scripts/build_entropy_test.sh --clean --flash --monitor
```

## Architecture

```text
Application
    -> entropy_get_entropy()
BLAKE2s Entropy Pool
    -> entropy_get_entropy() on backend_dev
ESP32 hardware entropy driver
```
