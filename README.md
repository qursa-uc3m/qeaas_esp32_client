# QEaaS ESP32 Client

Quantum Entropy as a Service (QEaaS) client for ESP32 using Zephyr RTOS. It retrieves quantum entropy over CoAP and mixes it with local hardware entropy in a custom BLAKE2s pool (Linux 5.17+ RNG inspired) and exposes a new system call for entropy injection.

## Core

* BLAKE2s entropy pool (`entropy_blake2s.c`) + Zephyr entropy API
* Entropy ingestion via CoAP client → `entropy_add_entropy()`

This client depends on a Zephyr fork ([fj-blanco/zephyr@entropy-pool](https://github.com/fj-blanco/zephyr/tree/entropy-pool)) that includes the custom BLAKE2s entropy pool driver. The `west.yml` manifest pulls this branch automatically.

## Architecture

```text
Application (main.c)
    ↓ entropy_get_entropy()
BLAKE2s Entropy Pool (entropy_blake2s.c)
    ↓ entropy_get_entropy() on backend_dev
Hardware Entropy Driver (e.g. ESP32 TRNG)
    ↓ hardware registers
Physical Entropy Source
```

## Setup

### Environment

```bash
conda create -n qeaas_esp32_client python=3.12 -y
conda activate qeaas_esp32_client
pip install -r requirements.txt  # installs west
```

### Zephyr Dependency

This client depends on a Zephyr fork that includes the custom BLAKE2s entropy pool driver:

* Zephyr fork: [fj-blanco/zephyr@entropy-pool](https://github.com/fj-blanco/zephyr/tree/entropy-pool)

The `west.yml` manifest pulls this branch automatically. Use upstream Zephyr only if you don't need the entropy pool enhancements.

### Build & Test Application (mbedTLS client)

```bash
./scripts/build.sh --wifi-ssid <SSID> --wifi-pass <PASS> --init
./scripts/build.sh --wifi-ssid <SSID> --wifi-pass <PASS> --clean --flash --monitor
```

## Devicetree Configuration

Add an overlay declaring the entropy pool and linking the hardware RNG:

```dts
/ {
    chosen {
        zephyr,entropy = &entropy_blake2s;
    };

    entropy_blake2s: entropy-blake2s-pool {
        compatible = "zephyr,entropy-blake2s-pool";
        hardware-device = <&trng0>;    // Your hardware entropy source
        status = "okay";
    };
};
```

## Related Projects

For wolfSSL + PQC CoAP client examples see: [coap-zephyr-clients](https://github.com/fj-blanco/coap-zephyr-clients)

This repository focuses on the entropy pool implementation and validation.
