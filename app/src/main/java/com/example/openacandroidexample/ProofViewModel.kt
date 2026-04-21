package com.example.openacandroidexample

import android.app.Application
import android.content.Intent
import android.net.Uri
import android.util.Base64
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import uniffi.mopro.generateCertChainRs4096Input
import uniffi.mopro.proveCertChainRs4096
import uniffi.mopro.proveDeviceSigRs2048
import uniffi.mopro.verifyCertChainRs4096
import uniffi.mopro.verifyDeviceSigRs2048
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.util.UUID
import java.util.zip.GZIPInputStream

private const val CERT_CHAIN_PROVING_KEY_URL =
    "https://github.com/zkmopro/zkID/releases/download/latest/cert_chain_rs4096_proving.key.gz"
private const val CERT_CHAIN_VERIFYING_KEY_URL =
    "https://github.com/zkmopro/zkID/releases/download/latest/cert_chain_rs4096_verifying.key.gz"
private const val DEVICE_SIG_PROVING_KEY_URL =
    "https://github.com/zkmopro/zkID/releases/download/latest/device_sig_rs2048_proving.key.gz"
private const val DEVICE_SIG_VERIFYING_KEY_URL =
    "https://github.com/zkmopro/zkID/releases/download/latest/device_sig_rs2048_verifying.key.gz"
private const val SMT_SNAPSHOT_URL =
    "https://github.com/moven0831/moica-revocation-smt/releases/download/snapshot-latest/g3-tree-snapshot.json.gz"

private const val CERT_CHAIN_PROVING_KEY_NAME  = "cert_chain_rs4096_proving.key"
private const val CERT_CHAIN_VERIFYING_KEY_NAME = "cert_chain_rs4096_verifying.key"
private const val DEVICE_SIG_PROVING_KEY_NAME   = "device_sig_rs2048_proving.key"
private const val DEVICE_SIG_VERIFYING_KEY_NAME  = "device_sig_rs2048_verifying.key"
private const val SMT_SNAPSHOT_NAME             = "g3-tree-snapshot.json.gz"

private const val SERVER_URL      = "https://435a-211-75-7-191.ngrok-free.app/challenge"
private const val LINK_VERIFY_URL = "https://435a-211-75-7-191.ngrok-free.app/link-verify"

const val RETURN_SCHEME = "openac"
const val RETURN_URL    = "$RETURN_SCHEME://callback"

class ProofViewModel(application: Application) : AndroidViewModel(application) {

    sealed class StepStatus {
        object Idle    : StepStatus()
        object Running : StepStatus()
        data class Success(val message: String) : StepStatus()
        data class Failure(val message: String) : StepStatus()

        val isSuccess: Boolean get() = this is Success
        val isRunning: Boolean get() = this is Running
    }

    // Pipeline step states
    var proveStatus:  StepStatus by mutableStateOf(StepStatus.Idle); private set
    var verifyStatus: StepStatus by mutableStateOf(StepStatus.Idle); private set
    var isRunning:    Boolean    by mutableStateOf(false);           private set

    // Circuit download state
    var circuitReady:     Boolean by mutableStateOf(false); private set
    var isDownloading:    Boolean by mutableStateOf(false); private set
    var downloadProgress: Double  by mutableStateOf(0.0);   private set
    var downloadError:    String? by mutableStateOf(null);  private set
    var downloadSeconds:  Double? by mutableStateOf(null);  private set

    // SP Ticket / MOICA
    var idNum:             String     by mutableStateOf("A123456789")
    var tbs:               String     by mutableStateOf("")
    var tbsStatus:         StepStatus by mutableStateOf(StepStatus.Idle); private set
    var spTicketStatus:    StepStatus by mutableStateOf(StepStatus.Idle); private set
    var spTicket:          String?    by mutableStateOf(null);             private set
    var rtnVal:            String?    by mutableStateOf(null);             private set
    var athResultStatus:   StepStatus by mutableStateOf(StepStatus.Idle); private set
    var athResponseString: String?    by mutableStateOf(null);             private set
    var athIssuerCert:     String?    by mutableStateOf(null);             private set

    var generateInputStatus: StepStatus by mutableStateOf(StepStatus.Idle); private set
    var generatedInputPath:  String?    by mutableStateOf(null);             private set
    var inputJson:           String?    by mutableStateOf(null);             private set

    // Paths
    private val workDir: File
        get() = File(getApplication<Application>().filesDir, "ZKVectors")

    val documentsPath: String get() = workDir.absolutePath
    val keysDir:       File   get() = File(workDir, "keys")

    init {
        checkCircuitReady()
    }

    private fun checkCircuitReady() {
        circuitReady = File(keysDir, CERT_CHAIN_PROVING_KEY_NAME).exists()
            && File(keysDir, DEVICE_SIG_PROVING_KEY_NAME).exists()
            && File(workDir, SMT_SNAPSHOT_NAME).exists()
    }

    // MARK: - Resource Setup

    fun prepareResources() {
        viewModelScope.launch(Dispatchers.IO) {
            val app = getApplication<Application>()
            workDir.mkdirs()
            // Copy input.json for emulator testing
            val inputDst = File(workDir, "input.json")
            if (!inputDst.exists()) {
                try {
                    app.assets.open("input.json")
                        .use { src -> inputDst.outputStream().use { src.copyTo(it) } }
                } catch (_: Exception) {}
            }
            // Copy MOICA-G3.cer from assets if not present
            val certDst = File(workDir, "MOICA-G3.cer")
            if (!certDst.exists()) {
                try {
                    app.assets.open("MOICA-G3.cer")
                        .use { src -> certDst.outputStream().use { src.copyTo(it) } }
                } catch (_: Exception) {}
            }
            checkCircuitReady()
        }
    }

    // MARK: - Download Circuit

    fun downloadCircuit() {
        if (isDownloading) return
        viewModelScope.launch {
            isDownloading    = true
            downloadProgress = 0.0
            downloadError    = null
            downloadSeconds  = null

            val certKeyExists  = File(keysDir, CERT_CHAIN_PROVING_KEY_NAME).exists()
            val devKeyExists   = File(keysDir, DEVICE_SIG_PROVING_KEY_NAME).exists()
            val snapshotExists = File(workDir, SMT_SNAPSHOT_NAME).exists()

            if (certKeyExists && devKeyExists && snapshotExists) {
                circuitReady  = true
                isDownloading = false
                return@launch
            }

            try {
                keysDir.mkdirs()
                val t0 = System.currentTimeMillis()

                data class Job(
                    val url: String,
                    val name: String,
                    val dest: File,
                    val exists: Boolean,
                    val decompress: Boolean,
                )
                val jobs = listOf(
                    Job(CERT_CHAIN_PROVING_KEY_URL, CERT_CHAIN_PROVING_KEY_NAME, File(keysDir, CERT_CHAIN_PROVING_KEY_NAME), certKeyExists, true),
                    Job(DEVICE_SIG_PROVING_KEY_URL, DEVICE_SIG_PROVING_KEY_NAME, File(keysDir, DEVICE_SIG_PROVING_KEY_NAME), devKeyExists, true),
                    Job(SMT_SNAPSHOT_URL,            SMT_SNAPSHOT_NAME,           File(workDir, SMT_SNAPSHOT_NAME),           snapshotExists, false),
                )
                val slice = 1.0 / jobs.size
                for ((i, job) in jobs.withIndex()) {
                    val base = i * slice
                    if (job.exists) {
                        downloadProgress = base + slice
                        continue
                    }
                    if (job.decompress) {
                        val tmp = File(getApplication<Application>().cacheDir, "${job.name}.gz")
                        downloadWithProgress(job.url, tmp) { downloadProgress = base + it * slice }
                        decompressGz(tmp, job.dest)
                    } else {
                        downloadWithProgress(job.url, job.dest) { downloadProgress = base + it * slice }
                    }
                }

                downloadSeconds = (System.currentTimeMillis() - t0) / 1000.0
                checkCircuitReady()
            } catch (e: Exception) {
                downloadError = e.message
            } finally {
                isDownloading = false
            }
        }
    }

    private suspend fun downloadWithProgress(
        url: String,
        dest: File,
        onProgress: (Double) -> Unit,
    ) = withContext(Dispatchers.IO) {
        val conn = URL(url).openConnection() as HttpURLConnection
        try {
            conn.connect()
            val total    = conn.contentLengthLong
            var received = 0L
            conn.inputStream.use { input ->
                dest.outputStream().use { output ->
                    val buf = ByteArray(65536)
                    var n: Int
                    while (input.read(buf).also { n = it } != -1) {
                        output.write(buf, 0, n)
                        received += n
                        if (total > 0) onProgress(received.toDouble() / total.toDouble())
                    }
                }
            }
        } finally {
            conn.disconnect()
        }
    }

    private suspend fun decompressGz(gzFile: File, dest: File) = withContext(Dispatchers.IO) {
        if (dest.exists()) dest.delete()
        GZIPInputStream(gzFile.inputStream().buffered()).use { gis ->
            dest.outputStream().use { gis.copyTo(it) }
        }
        gzFile.delete()
    }

    // MARK: - TBS Challenge

    fun regenerateTBS() {
        viewModelScope.launch {
            tbsStatus = StepStatus.Running
            try {
                val raw = withContext(Dispatchers.IO) {
                    val conn = URL(SERVER_URL).openConnection() as HttpURLConnection
                    conn.requestMethod = "POST"
                    conn.setRequestProperty("Content-Type", "application/json")
                    conn.setRequestProperty("ngrok-skip-browser-warning", "true")
                    conn.doOutput = true
                    conn.outputStream.use { it.write("{}".toByteArray()) }
                    val text = conn.inputStream.bufferedReader().readText()
                    conn.disconnect()
                    text
                }
                val json = JSONObject(raw)
                val challengeBytes = json.optString("challenge_bytes")
                if (challengeBytes.isEmpty()) throw Exception("challenge_bytes not found in response")
                tbs         = challengeBytes
                tbsStatus   = StepStatus.Success("challenge received")
            } catch (e: Exception) {
                tbsStatus = StepStatus.Failure(e.message ?: "unknown error")
            }
        }
    }

    // MARK: - SP Ticket / MOICA

    fun computeSPTicket() {
        viewModelScope.launch {
            spTicketStatus = StepStatus.Running
            spTicket       = null
            rtnVal         = null
            try {
                val raw = getSpTicket(
                    params = SpTicketParams(
                        transactionID = UUID.randomUUID().toString(),
                        idNum         = idNum,
                        opCode        = "SIGN",
                        opMode        = "APP2APP",
                        hint          = "待簽署資料",
                        timeLimit     = "600",
                        signData      = Base64.encodeToString(tbs.toByteArray(Charsets.UTF_8), Base64.NO_WRAP),
                        signType      = "PKCS#1",
                        hashAlgorithm = "SHA256",
                        tbsEncoding   = "base64",
                    )
                )
                val ticket = JSONObject(raw as String)
                    .optJSONObject("result")
                    ?.optString("sp_ticket")
                    ?.takeIf { it.isNotEmpty() }
                spTicket = ticket
                spTicketStatus = if (ticket != null)
                    StepStatus.Success("ticket received")
                else
                    StepStatus.Failure("sp_ticket not found in response: $raw")
            } catch (e: Exception) {
                spTicketStatus = StepStatus.Failure(e.message ?: "unknown error")
            }
        }
    }

    fun openMOICA() {
        val ticket = spTicket ?: return
        val rtnUrlBase64 = Base64.encodeToString(RETURN_URL.toByteArray(), Base64.NO_WRAP)
        val uri = Uri.Builder()
            .scheme("mobilemoica")
            .authority("moica.moi.gov.tw")
            .path("/a2a/verifySign")
            .appendQueryParameter("sp_ticket", ticket)
            .appendQueryParameter("rtn_url",   rtnUrlBase64)
            .appendQueryParameter("rtn_val",   "")
            .build()
        val intent = Intent(Intent.ACTION_VIEW, uri).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        getApplication<Application>().startActivity(intent)
    }

    fun pollAthResult() {
        viewModelScope.launch {
            athResultStatus = StepStatus.Running
            val ticket = spTicket
            if (ticket == null) {
                athResultStatus = StepStatus.Failure("No sp_ticket available")
                return@launch
            }
            try {
                val result = pollSignResult(spTicket = ticket)
                athResponseString = result.result?.signedResponse
                athIssuerCert     = result.result?.cert
                athResultStatus   = StepStatus.Success("result received")
            } catch (e: Exception) {
                athResultStatus = StepStatus.Failure(e.message ?: "unknown error")
            }
        }
    }

    fun handleCallback(uri: Uri) {
        if (uri.scheme != RETURN_SCHEME) return
        rtnVal = uri.getQueryParameter("rtn_val")
    }

    // MARK: - Pipeline

    fun reset() {
        generateInputStatus = StepStatus.Idle
        generatedInputPath  = null
        inputJson           = null
        proveStatus         = StepStatus.Idle
        verifyStatus        = StepStatus.Idle
    }

    fun runAll() {
        if (isRunning) return
        viewModelScope.launch {
            isRunning = true
            reset()
            doProve()
            if (!proveStatus.isSuccess) { isRunning = false; return@launch }
            doVerify()
            isRunning = false
        }
    }

    fun runGenerateInput() {
        viewModelScope.launch {
            generateInputStatus = StepStatus.Running
            val certb64        = athIssuerCert
            val signedResponse = athResponseString
            if (certb64 == null || signedResponse == null) {
                generateInputStatus = StepStatus.Failure("Missing ATH result — poll first")
                return@launch
            }
            val tbsCapture      = tbs
            val outDir          = workDir.absolutePath
            val issuerCertPath  = File(workDir, "MOICA-G3.cer").absolutePath
            val smtSnapshotPath = File(workDir, SMT_SNAPSHOT_NAME).absolutePath
            try {
                val resultPath = withContext(Dispatchers.Default) {
                    generateCertChainRs4096Input(
                        certb64         = certb64,
                        signedResponse  = signedResponse,
                        tbs             = tbsCapture,
                        issuerCertPath  = issuerCertPath,
                        smtSnapshotPath = smtSnapshotPath,
                        outputDir       = outDir,
                    )
                }
                generatedInputPath  = resultPath
                inputJson           = try { File(resultPath).readText() } catch (_: Exception) { null }
                generateInputStatus = StepStatus.Success(resultPath)
            } catch (e: Exception) {
                generateInputStatus = StepStatus.Failure(e.message ?: "unknown error")
            }
        }
    }

    fun runProve() {
        if (isRunning) return
        viewModelScope.launch {
            isRunning   = true
            proveStatus = StepStatus.Idle
            doProve()
            isRunning = false
        }
    }

    fun runVerify() {
        if (isRunning) return
        viewModelScope.launch {
            isRunning    = true
            verifyStatus = StepStatus.Idle
            doVerify()
            isRunning = false
        }
    }

    private suspend fun doProve() {
        proveStatus = StepStatus.Running
        val dp = documentsPath
        try {
            val ms = withContext(Dispatchers.Default) {
                val t0 = System.currentTimeMillis()
                proveCertChainRs4096(documentsPath = dp)
                proveDeviceSigRs2048(documentsPath = dp)
                System.currentTimeMillis() - t0
            }
            proveStatus = StepStatus.Success("$ms ms")
        } catch (e: Exception) {
            proveStatus = StepStatus.Failure(e.message ?: "unknown error")
        }
    }

    private suspend fun doVerify() {
        verifyStatus = StepStatus.Running

        // Download verifying keys on demand
        val verifyingKeys = listOf(
            CERT_CHAIN_VERIFYING_KEY_NAME  to CERT_CHAIN_VERIFYING_KEY_URL,
            DEVICE_SIG_VERIFYING_KEY_NAME  to DEVICE_SIG_VERIFYING_KEY_URL,
        )
        for ((keyName, remoteUrl) in verifyingKeys) {
            val dest = File(keysDir, keyName)
            if (dest.exists()) continue
            try {
                keysDir.mkdirs()
                val tmp = File(getApplication<Application>().cacheDir, "$keyName.gz")
                downloadWithProgress(remoteUrl, tmp) {}
                decompressGz(tmp, dest)
            } catch (e: Exception) {
                verifyStatus = StepStatus.Failure("Failed to download $keyName: ${e.message}")
                return
            }
        }

        val dp              = documentsPath
        val kd              = keysDir
        try {
            var ccProof     = ByteArray(0)
            var dsProof     = ByteArray(0)
            withContext(Dispatchers.Default) {
                ccProof = File(kd, "cert_chain_rs4096_proof.bin").readBytes()
                dsProof = File(kd, "device_sig_rs2048_proof.bin").readBytes()
            }

            var responseCode = 0
            var raw          = ""
            withContext(Dispatchers.IO) {
                val conn = URL(LINK_VERIFY_URL).openConnection() as HttpURLConnection
                conn.requestMethod = "POST"
                conn.setRequestProperty("Content-Type", "application/json")
                conn.setRequestProperty("ngrok-skip-browser-warning", "true")
                conn.doOutput = true
                val body = JSONObject().apply {
                    put("cert_chain_type",  "rs4096")
                    put("cert_chain_proof", Base64.encodeToString(ccProof, Base64.NO_WRAP))
                    put("device_sig_proof", Base64.encodeToString(dsProof, Base64.NO_WRAP))
                }
                conn.outputStream.use { it.write(body.toString().toByteArray()) }
                responseCode = conn.responseCode
                raw = try { conn.inputStream.bufferedReader().readText() }
                      catch (_: Exception) { conn.errorStream?.bufferedReader()?.readText() ?: "" }
                conn.disconnect()
            }

            if (responseCode != 200) {
                verifyStatus = StepStatus.Failure("link-verify failed ($responseCode): $raw")
                return
            }
            verifyStatus = StepStatus.Success("All proofs valid")
        } catch (e: Exception) {
            verifyStatus = StepStatus.Failure(e.message ?: "unknown error")
        }
    }
}
