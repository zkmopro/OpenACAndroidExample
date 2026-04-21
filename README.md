# OpenAC Android Example

An Android example app demonstrating zero-knowledge proof generation and verification using [OpenACKotlin](https://github.com/zkmopro/OpenACKotlin).

## Demo

| Download Circuit | FIDO Signature |
|:---:|:---:|
| ![Download Circuit](images/openac-android-download.gif) | ![FIDO Signature](images/openac-android-tw-fido.gif) |
| \~ 12 seconds | \~10 seconds |

| Generate Proof | Verify Proof |
|:---:|:---:|
| ![Generate Proof](images/openac-android-prove.gif) | ![Verify Proof](images/openac-android-verify.gif) |
| \~ 9 seconds | \~ 17 seconds |

## Overview

This app uses [OpenACKotlin](https://github.com/zkmopro/OpenACKotlin) to run the FIDO zkID circuit on Android. The single **zkID** tab exposes a scrollable screen with four cards that unlock sequentially:

### Circuit Download Card
Always visible. Shows a progress bar with the current file name and live percentage while fetching. The MOICA and ZK Pipeline cards are hidden until both the circuit and proving key are ready.

- **Download Circuit + Keys** — fetches and unzips `sha256rsa4096.r1cs` (circuit) and `rs256_4096_proving.key` (proving key) sequentially from their CDNs; shows download and unzip timings on completion

### MOICA Signature Card *(visible after circuit + keys are ready)*
Enter a masked **ID Number**, then follow the three numbered steps:

- **1. Get SP Ticket** — calls `getSpTicket` and displays the result
- **2. Open MOICA App** — launches the MOICA app via deep-link for the user to sign (app-to-app flow); enabled after an SP ticket is obtained
- **3. Poll ATH Result** — calls `getAthOrSignResult` and displays the signed response and cert snippets; enabled after an SP ticket is obtained

### fido_input.json Card *(visible after Generate Input completes)*
Expandable card showing the generated circuit input JSON, with a copy-to-clipboard button.

### ZK Pipeline Card *(visible after circuit + keys are ready)*
- **4. Generate Input** — calls `generateInputFido` to produce `fido_input.json` from the ATH result; enabled after ATH polling succeeds
- **5. Generate Proof** — calls `proveFido` and reports proof time (ms) and proof size (bytes)
- **6. Verify Proof** — calls `verifyFido` to confirm the proof is valid; downloads the verifying key on demand if not present; enabled after prove succeeds
- **Run All (Prove → Verify)** — convenience button that runs steps 5–6 in sequence (Generate Input must be run separately first)

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
| `ZkIdComponent.kt` | Compose UI — circuit download card, MOICA signature card, `fido_input.json` viewer card, ZK pipeline card |
| `FidoApi.kt` | MOICA FIDO REST API client (`getSpTicket`, `getAthOrSignResult`, `pollSignResult`, `computeSpChecksum`) |
| `Secrets.kt` | Fallback SP service credentials (git-ignored) |

## Dependencies

- [OpenACKotlin](https://github.com/zkmopro/OpenACKotlin) — Kotlin bindings for the mopro ZK proving backend (`generateInputFido`, `proveFido`, `verifyFido`)
