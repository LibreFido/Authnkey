package pl.lebihan.authnkey

/**
 * Transport type for FIDO authenticators
 */
enum class TransportType(val webauthnName: String) {
    USB("usb"),
    NFC("nfc")
}

/**
 * Common interface for FIDO transport (NFC or USB)
 */
interface FidoTransport {
    val transportType: TransportType
    val isConnected: Boolean

    @Throws(Exception::class)
    suspend fun sendCtapCommand(command: ByteArray): ByteArray

    fun close()
}
