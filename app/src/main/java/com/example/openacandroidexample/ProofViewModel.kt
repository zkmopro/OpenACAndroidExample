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
// import uniffi.mopro.generateInput
import uniffi.mopro.prove
import uniffi.mopro.setupKeys
import uniffi.mopro.verify
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.util.UUID
import java.util.zip.ZipInputStream

private const val CIRCUIT_ZIP_URL =
    "https://pub-ef10768896384fdf9617f26d43e11a65.r2.dev/sha256rsa4096.r1cs.zip"
private const val CIRCUIT_FILENAME = "sha256rsa4096.r1cs"

const val RETURN_SCHEME = "openac"
const val RETURN_URL    = "$RETURN_SCHEME://callback"

class ProofViewModel(application: Application) : AndroidViewModel(application) {

    // MARK: - Step Status

    sealed class StepStatus {
        object Idle    : StepStatus()
        object Running : StepStatus()
        data class Success(val message: String) : StepStatus()
        data class Failure(val message: String) : StepStatus()

        val isSuccess: Boolean get() = this is Success
        val isRunning: Boolean get() = this is Running
    }

    // MARK: - Pipeline state

    var setupStatus:   StepStatus by mutableStateOf(StepStatus.Idle); private set
    var proveStatus:   StepStatus by mutableStateOf(StepStatus.Idle); private set
    var verifyStatus:  StepStatus by mutableStateOf(StepStatus.Idle); private set
    var isRunning:     Boolean    by mutableStateOf(false);           private set

    // MARK: - Circuit download state

    var circuitReady:      Boolean  by mutableStateOf(false); private set
    var isDownloading:     Boolean  by mutableStateOf(false); private set
    var downloadProgress:  Double   by mutableStateOf(0.0);   private set
    var downloadError:     String?  by mutableStateOf(null);  private set
    var downloadSeconds:   Double?  by mutableStateOf(null);  private set
    var unzipSeconds:      Double?  by mutableStateOf(null);  private set

    // MARK: - SP Ticket / MOICA

    var idNum:               String     by mutableStateOf("A123456789")
    var spTicketStatus:      StepStatus by mutableStateOf(StepStatus.Idle); private set
    var spTicket:            String?    by mutableStateOf(null);             private set
    var rtnVal:              String?    by mutableStateOf(null);             private set
    var athResultStatus:     StepStatus by mutableStateOf(StepStatus.Idle); private set
    var athResponseString:   String?    by mutableStateOf(null);             private set
    var athIssuerCert:       String?    by mutableStateOf(null);             private set
    var generateInputStatus: StepStatus by mutableStateOf(StepStatus.Idle); private set

    // MARK: - Paths

    private val workDir: File
        get() = File(getApplication<Application>().filesDir, "ZKVectors")

    val documentsPath: String get() = workDir.absolutePath
    val inputPath:     String get() = File(workDir, "input.json").absolutePath

    init {
        checkCircuitReady()
    }

    private fun checkCircuitReady() {
        circuitReady = File(workDir, CIRCUIT_FILENAME).exists()
    }

    // MARK: - Resource Setup

    fun prepareResources() {
        viewModelScope.launch(Dispatchers.IO) {
            val app = getApplication<Application>()
            workDir.mkdirs()
            // Copy input.json from assets on first launch
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
            unzipSeconds     = null

            val tmpZip = File(getApplication<Application>().cacheDir, "sha256rsa4096.r1cs.zip")
            try {
                val t0 = System.currentTimeMillis()
                downloadWithProgress(CIRCUIT_ZIP_URL, tmpZip) { downloadProgress = it }
                downloadSeconds = (System.currentTimeMillis() - t0) / 1000.0

                val t1 = System.currentTimeMillis()
                unzipFile(tmpZip, workDir)
                tmpZip.delete()
                unzipSeconds = (System.currentTimeMillis() - t1) / 1000.0

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
                    val buf = ByteArray(8192)
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

    private suspend fun unzipFile(zip: File, destDir: File) = withContext(Dispatchers.IO) {
        ZipInputStream(zip.inputStream().buffered()).use { zis ->
            var entry = zis.nextEntry
            while (entry != null) {
                if (!entry.isDirectory) {
                    val out = File(destDir, entry.name)
                    out.parentFile?.mkdirs()
                    out.outputStream().use { zis.copyTo(it) }
                }
                zis.closeEntry()
                entry = zis.nextEntry
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
                        signData      = "ZTc3NWYyODA1ZmI5OTNlMDVhMjA4ZGJmZjE1ZDFjMQ==",
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
        setupStatus         = StepStatus.Idle
        proveStatus         = StepStatus.Idle
        verifyStatus        = StepStatus.Idle
    }

    fun runAll() {
        if (isRunning) return
        viewModelScope.launch {
            isRunning = true
            reset()
            doSetupKeys()
            if (!setupStatus.isSuccess)  { isRunning = false; return@launch }
            doProve()
            if (!proveStatus.isSuccess)  { isRunning = false; return@launch }
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
            val tbs            = "e775f2805fb993e05a208dbff15d1c1"
            val outPath        = File(workDir, "input.json").absolutePath
            val issuerCertPath = File(workDir, "MOICA-G3.cer").absolutePath
            try {
                withContext(Dispatchers.Default) {
                    // generateInput(
                    //     certb64        = certb64,
                    //     signedResponse = signedResponse,
                    //     tbs            = tbs,
                    //     issuerCertPath = issuerCertPath,
                    //     smtServer      = null,
                    //     issuerId       = "g2",
                    //     outputPath     = outPath,
                    // )
                }
                generateInputStatus = StepStatus.Success(outPath)
            } catch (e: Exception) {
                generateInputStatus = StepStatus.Failure(e.message ?: "unknown error")
            }
        }
    }

    fun runSetupKeys() { viewModelScope.launch { doSetupKeys() } }
    fun runProve()     { viewModelScope.launch { doProve() } }
    fun runVerify()    { viewModelScope.launch { doVerify() } }

    private suspend fun doSetupKeys() {
        setupStatus = StepStatus.Running
        val dp = documentsPath; val ip = inputPath
        try {
            val msg = withContext(Dispatchers.Default) {
                setupKeys(documentsPath = dp, inputPath = ip)
            }
            setupStatus = StepStatus.Success(msg)
        } catch (e: Exception) {
            setupStatus = StepStatus.Failure(e.message ?: "unknown error")
        }
    }

    private suspend fun doProve() {
        proveStatus = StepStatus.Running
        val dp = documentsPath; val ip = inputPath
        try {
            val result = withContext(Dispatchers.Default) {
                prove(documentsPath = dp, inputPath = ip)
            }
            proveStatus = StepStatus.Success("${result.proveMs} ms · ${result.proofSizeBytes} B")
        } catch (e: Exception) {
            proveStatus = StepStatus.Failure(e.message ?: "unknown error")
        }
    }

    private suspend fun doVerify() {
        verifyStatus = StepStatus.Running
        val dp = documentsPath
        try {
            val valid = withContext(Dispatchers.Default) { verify(documentsPath = dp) }
            verifyStatus = if (valid)
                StepStatus.Success("Proof is valid")
            else
                StepStatus.Failure("Proof is invalid")
        } catch (e: Exception) {
            verifyStatus = StepStatus.Failure(e.message ?: "unknown error")
        }
    }
}
