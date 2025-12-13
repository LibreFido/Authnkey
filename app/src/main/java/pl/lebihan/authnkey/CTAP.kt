package pl.lebihan.authnkey

data class AlgorithmInfo(
    val type: String?,
    val alg: Int?
)

data class DeviceInfo(
    val versions: List<String> = emptyList(),
    val extensions: List<String> = emptyList(),
    val aaguid: ByteArray? = null,
    val options: Map<String, Boolean> = emptyMap(),
    val maxMsgSize: Int? = null,
    val pinUvAuthProtocols: List<Int> = emptyList(),
    val maxCredentialCountInList: Int? = null,
    val maxCredentialIdLength: Int? = null,
    val transports: List<String> = emptyList(),
    val algorithms: List<AlgorithmInfo> = emptyList(),
    val firmwareVersion: Int? = null,
    val minPinLength: Int? = null
) {
    val supportsCredMgmt: Boolean
        get() = options["credMgmt"] == true

    val supportsCredMgmtPreview: Boolean
        get() = options["credentialMgmtPreview"] == true

    val usePreviewCommand: Boolean
        get() = supportsCredMgmtPreview && !supportsCredMgmt
}

object CTAP {
    const val CMD_MAKE_CREDENTIAL = 0x01
    const val CMD_GET_ASSERTION = 0x02
    const val CMD_GET_INFO = 0x04
    const val CMD_CLIENT_PIN = 0x06
    const val CMD_RESET = 0x07
    const val CMD_GET_NEXT_ASSERTION = 0x08
    const val CMD_CREDENTIAL_MANAGEMENT = 0x0A
    const val CMD_CREDENTIAL_MANAGEMENT_PREVIEW = 0x41
    const val CMD_SELECTION = 0x0B
    const val CMD_LARGE_BLOBS = 0x0C
    const val CMD_CONFIG = 0x0D

    const val PIN_CMD_GET_RETRIES = 0x01
    const val PIN_CMD_GET_KEY_AGREEMENT = 0x02
    const val PIN_CMD_SET_PIN = 0x03
    const val PIN_CMD_CHANGE_PIN = 0x04
    const val PIN_CMD_GET_PIN_TOKEN = 0x05

    private const val STATUS_SUCCESS: Byte = 0x00

    enum class Error(val code: Int) {
        SUCCESS(0x00),
        INVALID_COMMAND(0x01),
        INVALID_PARAMETER(0x02),
        INVALID_LENGTH(0x03),
        INVALID_SEQ(0x04),
        TIMEOUT(0x05),
        CHANNEL_BUSY(0x06),
        LOCK_REQUIRED(0x0A),
        INVALID_CHANNEL(0x0B),
        CBOR_UNEXPECTED_TYPE(0x11),
        INVALID_CBOR(0x12),
        MISSING_PARAMETER(0x14),
        LIMIT_EXCEEDED(0x15),
        CREDENTIAL_EXCLUDED(0x19),
        PROCESSING(0x21),
        INVALID_CREDENTIAL(0x22),
        USER_ACTION_PENDING(0x23),
        OPERATION_PENDING(0x24),
        NO_OPERATIONS(0x25),
        UNSUPPORTED_ALGORITHM(0x26),
        OPERATION_DENIED(0x27),
        KEY_STORE_FULL(0x28),
        UNSUPPORTED_OPTION(0x2B),
        INVALID_OPTION(0x2C),
        KEEPALIVE_CANCEL(0x2D),
        NO_CREDENTIALS(0x2E),
        USER_ACTION_TIMEOUT(0x2F),
        NOT_ALLOWED(0x30),
        PIN_INVALID(0x31),
        PIN_BLOCKED(0x32),
        PIN_AUTH_INVALID(0x33),
        PIN_AUTH_BLOCKED(0x34),
        PIN_NOT_SET(0x35),
        PIN_REQUIRED(0x36),
        PIN_POLICY_VIOLATION(0x37),
        PIN_TOKEN_EXPIRED(0x38),
        REQUEST_TOO_LARGE(0x39),
        ACTION_TIMEOUT(0x3A),
        UP_REQUIRED(0x3B),
        UV_BLOCKED(0x3C),
        INTEGRITY_FAILURE(0x3D),
        INVALID_SUBCOMMAND(0x3E),
        UV_INVALID(0x3F),
        UNAUTHORIZED_PERMISSION(0x40),
        OTHER(0x7F);

        companion object {
            private val byCode = entries.associateBy { it.code }
            fun fromCode(code: Int): Error? = byCode[code]
        }
    }

    fun getErrorName(code: Byte): String {
        val intCode = code.toInt() and 0xFF
        return Error.fromCode(intCode)?.name ?: "UNKNOWN_ERROR (0x${String.format("%02X", code)})"
    }

    fun isSuccess(response: ByteArray): Boolean {
        return response.isNotEmpty() && response[0] == STATUS_SUCCESS
    }

    fun getResponseError(response: ByteArray): Error? {
        if (response.isEmpty()) return Error.OTHER
        val code = response[0].toInt() and 0xFF
        return if (code == 0) null else (Error.fromCode(code) ?: Error.OTHER)
    }

    fun getResponseErrorMessage(response: ByteArray): String? {
        if (response.isEmpty()) return "Empty response"
        val code = response[0].toInt() and 0xFF
        return if (code == 0) null else getErrorName(response[0])
    }

    fun buildCommand(cmd: Int): ByteArray {
        return byteArrayOf(cmd.toByte())
    }

    fun parseGetInfoStructured(response: ByteArray): DeviceInfo? {
        if (!isSuccess(response)) {
            return null
        }

        val data = response.drop(1).toByteArray()

        return try {
            val parsed = CborMap.decode(data) ?: return null

            val versions = parsed.list<String>(1) ?: emptyList()
            val extensions = parsed.list<String>(2) ?: emptyList()
            val aaguid = parsed.bytes(3)

            val options = mutableMapOf<String, Boolean>()
            parsed.map(4)?.let { opts ->
                val raw = CborDecoder.decode(data) as? Map<*, *>
                (raw?.get(4L) as? Map<*, *>)?.forEach { (k, v) ->
                    if (k is String && v is Boolean) {
                        options[k] = v
                    }
                }
            }

            val maxMsgSize = parsed.int(5)
            val pinUvAuthProtocols = parsed.list<Long>(6)?.map { it.toInt() } ?: emptyList()
            val maxCredentialCountInList = parsed.int(7)
            val maxCredentialIdLength = parsed.int(8)
            val transports = parsed.list<String>(9) ?: emptyList()

            val algorithms = parsed.mapList(10)?.mapNotNull { alg ->
                AlgorithmInfo(
                    type = alg.string("type"),
                    alg = alg.int("alg")
                )
            } ?: emptyList()

            val minPinLength = parsed.int(13)
            val firmwareVersion = parsed.int(14)

            DeviceInfo(
                versions = versions,
                extensions = extensions,
                aaguid = aaguid,
                options = options,
                maxMsgSize = maxMsgSize,
                pinUvAuthProtocols = pinUvAuthProtocols,
                maxCredentialCountInList = maxCredentialCountInList,
                maxCredentialIdLength = maxCredentialIdLength,
                transports = transports,
                algorithms = algorithms,
                firmwareVersion = firmwareVersion,
                minPinLength = minPinLength
            )
        } catch (e: Exception) {
            null
        }
    }

    fun buildGetPinRetriesCommand(): ByteArray {
        return byteArrayOf(CMD_CLIENT_PIN.toByte()) + cbor {
            map {
                1 to 1
                2 to 1
            }
        }
    }
}
