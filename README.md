# OpenAC Android Example

An Android example app demonstrating zero-knowledge proof generation and verification using [OpenACKotlin](https://github.com/zkmopro/OpenACKotlin).

## Demo

| Download Circuit | FIDO Signature |
|:---:|:---:|
| ![Download Circuit](images/openac-android-download.gif) | ![FIDO Signature](images/openac-android-fido.gif) |
| \~ 19 seconds | \~8 seconds |

| Generate Proof | Verify Proof |
|:---:|:---:|
| ![Generate Proof](images/openac-android-prove.gif) | ![Verify Proof](images/openac-android-verify.gif) |
| \~ 21 seconds | \~ 20 seconds |

## Overview

This app uses [OpenACKotlin](https://github.com/zkmopro/OpenACKotlin) to run the FIDO zkID circuit on Android. It demonstrates a full end-to-end zero-knowledge proof workflow:

1. **Download Circuit** — downloads and unzips `sha256rsa4096.r1cs` from a CDN at runtime, showing live download progress
2. **MOICA Signature** — calls the MOICA FIDO API to:
   - Get an SP ticket (`getSpTicket`)
   - Open the MOICA mobile app for the user to sign via app-to-app flow
   - Poll for the signed ATH result (`getAthOrSignResult`)
3. **ZK Pipeline** — runs the four-step ZK workflow:
   - **Generate Input** — calls `generateInputFido` to produce `fido_input.json` from the signed ATH response
   - **Setup Keys** — generates proving and verifying keys from the circuit via `setupKeysFido`
   - **Generate Proof** — produces a zero-knowledge proof via `proveFido`, reporting proof time and size
   - **Verify Proof** — verifies the proof is valid via `verifyFido`

## Getting Started

Clone the repo and open it in Android Studio.

```bash
git clone https://github.com/zkmopro/OpenACAndroidExample
```

### Configuration — `Secrets.kt`

The app requires FIDO SP service credentials. Create or update the file below **before building** (it is git-ignored):

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
| `fidoAESKey` | 32-byte AES-256 key (base64-encoded) used to compute `sp_checksum` via AES-256-GCM |

Credentials can also be supplied at test time via environment variables `FIDO_SP_SERVICE_ID` and `FIDO_AES_KEY`; the app falls back to `Secrets.kt` if those are absent.

The app requires an internet connection on first launch to download the circuit file from the CDN.

## Architecture

| File | Description |
|---|---|
| `MainActivity.kt` | Entry point; wires the MOICA app2app callback URI into the ViewModel |
| `ProofViewModel.kt` | All state and business logic — download, MOICA API calls, ZK pipeline |
| `ZkIdComponent.kt` | Compose UI — circuit download card, MOICA signature card, ZK pipeline card |
| `FidoApi.kt` | MOICA FIDO REST API client (`getSpTicket`, `getAthOrSignResult`, `pollSignResult`, `computeSpChecksum`) |
| `Secrets.kt` | Fallback SP service credentials (git-ignored) |

## Dependencies

- [OpenACKotlin](https://github.com/zkmopro/OpenACKotlin) — Kotlin bindings for the mopro ZK proving backend (`generateInputFido`, `setupKeysFido`, `proveFido`, `verifyFido`)
