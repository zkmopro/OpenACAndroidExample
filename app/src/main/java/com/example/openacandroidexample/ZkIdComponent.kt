package com.example.openacandroidexample

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import uniffi.mopro.ProofResult
import uniffi.mopro.prove
import uniffi.mopro.setupKeys
import uniffi.mopro.verify

@Composable
fun ZkIdComponent() {
    val context = LocalContext.current
    val documentsPath = context.filesDir.absolutePath
    val inputPath = getFilePathFromAssets("input.json")

    var isDownloadingR1cs by remember { mutableStateOf(true) }
    var downloadError by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(Unit) {
        try {
            downloadAndUnzipToFilesDir(
                context,
                "https://github.com/zkmopro/zkID/releases/download/latest/rs256.r1cs.zip",
                "rs256.r1cs"
            )
        } catch (e: Exception) {
            downloadError = e.message
        } finally {
            isDownloadingR1cs = false
        }
    }

    var isSettingUpKeys by remember { mutableStateOf(false) }
    var isProving by remember { mutableStateOf(false) }
    var isVerifying by remember { mutableStateOf(false) }

    var setupResult by remember { mutableStateOf<String?>(null) }
    var proofResult by remember { mutableStateOf<ProofResult?>(null) }
    var verifyResult by remember { mutableStateOf<Boolean?>(null) }
    var errorMessage by remember { mutableStateOf<String?>(null) }

    val isBusy = isDownloadingR1cs || isSettingUpKeys || isProving || isVerifying
    val scrollState = rememberScrollState()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(scrollState)
            .padding(horizontal = 16.dp, vertical = 8.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(4.dp)
        ) {
            Text(
                text = "zkID RS256",
                style = MaterialTheme.typography.headlineSmall,
                fontWeight = FontWeight.Bold
            )
            Text(
                text = "Zero-knowledge proof of RS256 JWT signature",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center
            )
        }

        AnimatedVisibility(visible = isDownloadingR1cs || downloadError != null) {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(
                    containerColor = if (downloadError != null)
                        MaterialTheme.colorScheme.errorContainer
                    else
                        MaterialTheme.colorScheme.secondaryContainer
                )
            ) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Text(
                        text = if (downloadError != null) "Download failed" else "Fetching circuit file",
                        style = MaterialTheme.typography.labelLarge,
                        fontWeight = FontWeight.SemiBold,
                        color = if (downloadError != null)
                            MaterialTheme.colorScheme.onErrorContainer
                        else
                            MaterialTheme.colorScheme.onSecondaryContainer
                    )
                    if (downloadError != null) {
                        Text(
                            text = downloadError!!,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onErrorContainer
                        )
                    } else {
                        LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                        Text(
                            text = "rs256.r1cs",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSecondaryContainer
                        )
                    }
                }
            }
        }

        if (!isDownloadingR1cs && downloadError == null) {
            ElevatedCard(modifier = Modifier.fillMaxWidth()) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    Text(
                        "Actions",
                        style = MaterialTheme.typography.labelLarge,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )

                    StepButton(
                        label = "1. Setup Keys",
                        statusLabel = when {
                            isSettingUpKeys -> "Running…"
                            setupResult != null -> "Done"
                            else -> null
                        },
                        isRunning = isSettingUpKeys,
                        isDone = setupResult != null,
                        enabled = !isBusy,
                        testTag = "zkidSetupKeysButton",
                        onClick = {
                            isSettingUpKeys = true
                            setupResult = null
                            errorMessage = null
                            Thread {
                                try {
                                    setupResult = setupKeys(documentsPath, inputPath)
                                } catch (e: Exception) {
                                    errorMessage = "Setup failed: ${e.message}"
                                    e.printStackTrace()
                                } finally {
                                    isSettingUpKeys = false
                                }
                            }.start()
                        }
                    )

                    StepButton(
                        label = "2. Generate Proof",
                        statusLabel = when {
                            isProving -> "Running…"
                            proofResult != null -> "Done"
                            else -> null
                        },
                        isRunning = isProving,
                        isDone = proofResult != null,
                        enabled = !isBusy && setupResult != null,
                        testTag = "zkidProveButton",
                        onClick = {
                            isProving = true
                            proofResult = null
                            verifyResult = null
                            errorMessage = null
                            Thread {
                                try {
                                    proofResult = prove(documentsPath, inputPath)
                                } catch (e: Exception) {
                                    errorMessage = "Prove failed: ${e.message}"
                                    e.printStackTrace()
                                } finally {
                                    isProving = false
                                }
                            }.start()
                        }
                    )

                    StepButton(
                        label = "3. Verify Proof",
                        statusLabel = when {
                            isVerifying -> "Running…"
                            verifyResult != null -> if (verifyResult!!) "Valid" else "Invalid"
                            else -> null
                        },
                        isRunning = isVerifying,
                        isDone = verifyResult != null,
                        isSuccess = verifyResult == true,
                        enabled = !isBusy && proofResult != null,
                        testTag = "zkidVerifyButton",
                        onClick = {
                            isVerifying = true
                            verifyResult = null
                            errorMessage = null
                            Thread {
                                try {
                                    verifyResult = verify(documentsPath)
                                } catch (e: Exception) {
                                    errorMessage = "Verify failed: ${e.message}"
                                    e.printStackTrace()
                                } finally {
                                    isVerifying = false
                                }
                            }.start()
                        }
                    )
                }
            }
        }

        if (setupResult != null || proofResult != null || verifyResult != null || errorMessage != null) {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
            ) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Text(
                        "Results",
                        style = MaterialTheme.typography.labelLarge,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    HorizontalDivider()
                    setupResult?.let { ResultRow("Setup", it) }
                    proofResult?.let {
                        ResultRow("Prove time", "${it.proveMs} ms")
                        ResultRow("Proof size", "${it.proofSizeBytes} bytes")
                    }
                    verifyResult?.let { valid ->
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(
                                "Valid",
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                            Text(
                                if (valid) "✓  true" else "✗  false",
                                style = MaterialTheme.typography.bodyMedium,
                                fontWeight = FontWeight.SemiBold,
                                color = if (valid) Color(0xFF2E7D32) else MaterialTheme.colorScheme.error
                            )
                        }
                    }
                    errorMessage?.let {
                        HorizontalDivider(color = MaterialTheme.colorScheme.error.copy(alpha = 0.3f))
                        Text(
                            it,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.error
                        )
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(16.dp))
    }
}

@Composable
private fun StepButton(
    label: String,
    statusLabel: String?,
    isRunning: Boolean,
    isDone: Boolean,
    enabled: Boolean,
    testTag: String,
    isSuccess: Boolean = isDone,
    onClick: () -> Unit
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        Button(
            onClick = onClick,
            modifier = Modifier
                .weight(1f)
                .testTag(testTag),
            enabled = enabled
        ) {
            if (isRunning) {
                CircularProgressIndicator(
                    modifier = Modifier.size(16.dp),
                    color = MaterialTheme.colorScheme.onPrimary,
                    strokeWidth = 2.dp
                )
                Spacer(Modifier.width(8.dp))
            }
            Text(label)
        }
        if (statusLabel != null) {
            val badgeColor = when {
                isRunning -> MaterialTheme.colorScheme.secondary
                isSuccess -> Color(0xFF2E7D32)
                else -> MaterialTheme.colorScheme.error
            }
            Surface(
                shape = MaterialTheme.shapes.small,
                color = badgeColor.copy(alpha = 0.15f)
            ) {
                Text(
                    statusLabel,
                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
                    style = MaterialTheme.typography.labelSmall,
                    color = badgeColor,
                    fontWeight = FontWeight.SemiBold
                )
            }
        }
    }
}

@Composable
private fun ResultRow(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(label, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(value, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.Medium)
    }
}
