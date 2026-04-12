# OpenAC Android Example

An Android example app demonstrating zero-knowledge proof generation and verification using [OpenACKotlin](https://github.com/zkmopro/OpenACKotlin).

## Screenshot

![Android Screenshot](images/Android-screenshot.jpeg)

## Overview

This app uses [OpenACKotlin](https://github.com/zkmopro/OpenACKotlin) to run the FIDO zkID circuit on Android. It:

1. Downloads the circuit file (`sha256rsa4096.r1cs`) at runtime
2. Calls the MOICA FIDO API to obtain an SP ticket and initiate an app2app signature flow
3. Polls for the signed ATH result and uses it to generate the ZK circuit input
4. Runs the three-step ZK workflow:
   - **Setup Keys** — generates proving and verifying keys from the circuit
   - **Generate Proof** — produces a zero-knowledge proof from the input
   - **Verify Proof** — verifies the proof is valid

## Getting Started

Clone the repo and open it in Android Studio.

```bash
git clone https://github.com/zkmopro/OpenACAndroidExample
```

### Configuration — `Secrets.kt`

The app requires FIDO SP service credentials. Create the file below **before building** (it is git-ignored):

```
app/src/main/java/com/example/openacandroidexample/Secrets.kt
```

```kotlin
package com.example.openacandroidexample

object Secrets {
    const val fidoSpServiceID: String = "your-sp-service-id"
    const val fidoAESKey: String = "your-32-byte-aes-key-base64"
}
```

| Constant | Description |
|---|---|
| `fidoSpServiceID` | SP service ID issued by MOICA |
| `fidoAESKey` | 32-byte AES-256 key (base64-encoded) used to compute `sp_checksum` |

The app requires an internet connection on first launch to download the circuit file from the FIDO CDN.

## Dependencies

- [OpenACKotlin](https://github.com/zkmopro/OpenACKotlin) — Kotlin bindings for the mopro ZK proving backend
