package com.example.openacandroidexample

import android.util.Base64
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

// MARK: - Configuration

private fun getSpServiceID(): String =
    System.getenv("FIDO_SP_SERVICE_ID") ?: Secrets.fidoSpServiceID

private fun getAESKeyBase64(): String =
    System.getenv("FIDO_AES_KEY") ?: Secrets.fidoAESKey

private const val BASE_URL = "https://fidoapi.moi.gov.tw"

// MARK: - Models

data class SpTicketParams(
    val transactionID: String,
    val idNum: String,
    val opCode: String,       // "SIGN" | "ATH" | "NFCSIGN"
    val opMode: String,       // "APP2APP" | "I-SCAN" | …
    val hint: String,
    val timeLimit: String,    // e.g. "600"
    val signData: String,     // base64 string
    val signType: String,     // "PKCS#7" | "CMS" | "RAW"
    val hashAlgorithm: String,
    val tbsEncoding: String,  // "base64" | "utf8"
)

data class SpTicketPayload(
    val transactionID: String,
    val spTicketID: String,
    val opCode: String,
)

data class SignResult(
    val hashedIDNum: String?,
    val signedResponse: String?,
    val idpChecksum: String?,
    val cert: String?,
)

data class AthOrSignResultResponse(
    val errorCode: String,
    val errorMessage: String,
    val result: SignResult?,
)

// MARK: - Errors

sealed class FIDOError(message: String) : Exception(message) {
    class InvalidAESKey : FIDOError("Invalid AES key")
    class EncryptionFailed : FIDOError("Encryption failed")
    class InvalidSpTicket(reason: String) : FIDOError("Invalid sp_ticket: $reason")
    class HttpError(code: Int) : FIDOError("HTTP error: $code")
    class DecodingError(reason: String) : FIDOError("Decoding error: $reason")
}

// MARK: - Checksum

/**
 * Implements the 5-step sp_checksum algorithm from the spec:
 * 1. Decode the AES-256 key from base64.
 * 2. SHA-256 the payload → hex string.
 * 3. Use a zero 12-byte IV.
 * 4. AES-256-GCM encrypt the hex string (128-bit tag appended by JCE).
 * 5. Return hex(IV) + hex(ciphertext + tag).
 */
fun computeSpChecksum(payload: String): String {
    // [2] SHA-256 → hex string
    val sha256Bytes = MessageDigest.getInstance("SHA-256")
        .digest(payload.toByteArray(Charsets.UTF_8))
    val sha256Hex = sha256Bytes.joinToString("") { "%02x".format(it) }

    // [1] decode AES key
    val keyData = try {
        Base64.decode(getAESKeyBase64(), Base64.DEFAULT)
    } catch (_: Exception) {
        throw FIDOError.InvalidAESKey()
    }
    if (keyData.size != 32) throw FIDOError.InvalidAESKey()

    // [3] zero IV (12 bytes)
    val iv = ByteArray(12)

    // [4] AES-256-GCM encrypt (JCE appends the 16-byte tag after the ciphertext)
    val ciphertextWithTag = try {
        Cipher.getInstance("AES/GCM/NoPadding").run {
            init(Cipher.ENCRYPT_MODE, SecretKeySpec(keyData, "AES"), GCMParameterSpec(128, iv))
            doFinal(sha256Hex.toByteArray(Charsets.UTF_8))
        }
    } catch (_: Exception) {
        throw FIDOError.EncryptionFailed()
    }

    // [5] hex(iv) + hex(ciphertext + tag)
    val ivHex = iv.joinToString("") { "%02x".format(it) }
    val ctHex = ciphertextWithTag.joinToString("") { "%02x".format(it) }
    return ivHex + ctHex
}

// MARK: - sp_ticket decode

/**
 * Splits "Payload.Digest" on the last '.' and base64url-decodes the Payload segment.
 */
fun decodeSpTicket(spTicket: String): SpTicketPayload {
    val dotIndex = spTicket.lastIndexOf('.')
    if (dotIndex < 0) throw FIDOError.InvalidSpTicket("missing '.' separator")

    val payloadB64 = spTicket.substring(0, dotIndex)

    // base64url → standard base64, add padding
    var base64 = payloadB64.replace('-', '+').replace('_', '/')
    val remainder = base64.length % 4
    if (remainder > 0) base64 += "=".repeat(4 - remainder)

    val raw = try {
        Base64.decode(base64, Base64.DEFAULT)
    } catch (_: Exception) {
        throw FIDOError.InvalidSpTicket("base64 decode failed")
    }

    return try {
        val json = JSONObject(raw.toString(Charsets.UTF_8))
        SpTicketPayload(
            transactionID = json.getString("transaction_id"),
            spTicketID    = json.getString("sp_ticket_id"),
            opCode        = json.getString("op_code"),
        )
    } catch (e: Exception) {
        throw FIDOError.InvalidSpTicket("JSON decode failed: ${e.message}")
    }
}

// MARK: - API: getSpTicket

suspend fun getSpTicket(params: SpTicketParams): String = withContext(Dispatchers.IO) {
    val payload = params.transactionID + getSpServiceID() + params.idNum +
            params.opCode + params.opMode + params.hint + params.signData
    val checksum = computeSpChecksum(payload)
    println("checksum: $checksum")
    println("payload: $payload")

    val body = JSONObject().apply {
        put("transaction_id", params.transactionID)
        put("sp_service_id",  getSpServiceID())
        put("sp_checksum",    checksum)
        put("id_num",         params.idNum)
        put("op_code",        params.opCode)
        put("op_mode",        params.opMode)
        put("hint",           params.hint)
        put("time_limit",     params.timeLimit)
        put("sign_info", JSONObject().apply {
            put("tbs_encoding",   params.tbsEncoding)
            put("sign_data",      params.signData)
            put("hash_algorithm", params.hashAlgorithm)
            put("sign_type",      params.signType)
        })
    }

    val connection = URL("$BASE_URL/moise/sp/getSpTicket").openConnection() as HttpURLConnection
    try {
        connection.requestMethod = "POST"
        connection.setRequestProperty("Content-Type", "application/json; charset=utf-8")
        connection.doOutput = true
        connection.outputStream.use { it.write(body.toString().toByteArray(Charsets.UTF_8)) }

        val statusCode = connection.responseCode
        if (statusCode != HttpURLConnection.HTTP_OK) throw FIDOError.HttpError(statusCode)

        connection.inputStream.use { it.readBytes().toString(Charsets.UTF_8) }
    } finally {
        connection.disconnect()
    }
}

// MARK: - API: getAthOrSignResult

/**
 * Per spec, callers should wait at least 4 seconds between poll attempts.
 */
suspend fun getAthOrSignResult(spTicket: String): AthOrSignResultResponse = withContext(Dispatchers.IO) {
    val ticket = decodeSpTicket(spTicket)

    val payload = ticket.transactionID + getSpServiceID() + ticket.spTicketID
    val checksum = computeSpChecksum(payload)

    val body = JSONObject().apply {
        put("transaction_id", ticket.transactionID)
        put("sp_service_id",  getSpServiceID())
        put("sp_checksum",    checksum)
        put("sp_ticket_id",   ticket.spTicketID)
    }

    val connection = URL("$BASE_URL/moise/sp/getAthOrSignResult").openConnection() as HttpURLConnection
    try {
        connection.requestMethod = "POST"
        connection.setRequestProperty("Content-Type", "application/json; charset=utf-8")
        connection.doOutput = true
        connection.outputStream.use { it.write(body.toString().toByteArray(Charsets.UTF_8)) }

        val statusCode = connection.responseCode
        if (statusCode != HttpURLConnection.HTTP_OK) throw FIDOError.HttpError(statusCode)

        val responseText = connection.inputStream.use { it.readBytes().toString(Charsets.UTF_8) }
        parseAthOrSignResultResponse(responseText)
    } finally {
        connection.disconnect()
    }
}

private fun parseAthOrSignResultResponse(json: String): AthOrSignResultResponse {
    return try {
        val obj = JSONObject(json)
        val resultObj = if (obj.has("result") && !obj.isNull("result")) {
            val r = obj.getJSONObject("result")
            SignResult(
                hashedIDNum    = r.optString("hashed_id_num").takeIf { it.isNotEmpty() },
                signedResponse = r.optString("signed_response").takeIf { it.isNotEmpty() },
                idpChecksum    = r.optString("idp_checksum").takeIf { it.isNotEmpty() },
                cert           = r.optString("cert").takeIf { it.isNotEmpty() },
            )
        } else null
        AthOrSignResultResponse(
            errorCode    = obj.getString("error_code"),
            errorMessage = obj.getString("error_message"),
            result       = resultObj,
        )
    } catch (e: Exception) {
        throw FIDOError.DecodingError(e.message ?: "unknown")
    }
}

// MARK: - Poll Sign Result

suspend fun pollSignResult(spTicket: String): AthOrSignResultResponse {
    while (true) {
        val result = getAthOrSignResult(spTicket)
        when (result.errorCode) {
            "0" -> return result
            "20002", "20003" -> {
                println("Waiting for user action...")
                delay(4_000)
            }
            else -> throw FIDOError.DecodingError(
                "error ${result.errorCode}: ${result.errorMessage}"
            )
        }
    }
}
