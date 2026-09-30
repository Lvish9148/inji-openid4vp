package io.mosip.openID4VP.jwt.jwe

import io.mockk.*
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadataDraft23
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadataDraft23Serializer
import io.mosip.openID4VP.authorizationRequest.clientMetadata.Jwk
import io.mosip.openID4VP.authorizationRequest.deserializeAndValidate
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.jwt.jwe.encryption.EncryptionProvider
import io.mosip.openID4VP.testData.clientMetadataString
import kotlin.test.*
private const val ECDH_ES = "ECDH-ES"
class JWEHandlerTest {

    private lateinit var clientMetadata: ClientMetadataDraft23
    private lateinit var jweHandler: JWEHandler
    private lateinit var publicKey: Jwk
    private val walletNonce = "d2FsbGV0MTIz"
    private val verifierNonce = "dmVyaWZpZXI0NTY"

    @BeforeTest
    fun setUp() {
        clientMetadata = deserializeAndValidate(clientMetadataString, ClientMetadataDraft23Serializer)
        publicKey = clientMetadata.jwks!!.keys[1]
        jweHandler = JWEHandler(
            ECDH_ES,
            "A256GCM",
            publicKey,
            walletNonce,
            verifierNonce
        )

    }

    @AfterTest
    fun tearDown() {
        clearAllMocks()
    }

    @Test
    fun `should generate encrypted response successfully`() {
        val payload = mapOf("key1" to "value1", "key2" to 123)

        val encryptedResponse = jweHandler.generateEncryptedResponse(payload)

        assertNotNull(encryptedResponse)
        assertTrue(encryptedResponse.isNotEmpty())
        assertEquals(5, encryptedResponse.split(".").size)
    }

    @Test
    fun `should throw exception when encryption fails`() {
        val payload = mapOf("key1" to "value1")

        mockkObject(EncryptionProvider)
        every { EncryptionProvider.getEncrypter(any()) } throws RuntimeException("Key agreement failed")

        val handler = JWEHandler(ECDH_ES, "A256GCM", publicKey, walletNonce, verifierNonce)
        val exception = assertFailsWith<OpenID4VPExceptions> {
            handler.generateEncryptedResponse(payload)
        }

        assertTrue(exception.message?.contains("Encryption failed") ?: false)
    }

    @Test
    fun `should throw exception when JWT encryption fails`() {
        val payload = mapOf("key1" to "value1")

        mockkObject(EncryptionProvider)
        every { EncryptionProvider.getEncrypter(any()) } throws RuntimeException("Encryption error")

        val handler = JWEHandler(ECDH_ES, "A256GCM", publicKey, walletNonce, verifierNonce)
        val exception = assertFailsWith<OpenID4VPExceptions.JweEncryptionFailure> {
            handler.generateEncryptedResponse(payload)
        }
        assertTrue(exception.message!!.contains("JWE Encryption failed"))
    }

    @Test
    fun `should throw UnsupportedOperationException when keyEncryptionAlg is unsupported`() {
        val payload = mapOf("key1" to "value1")
        val handler = JWEHandler("RSA-OAEP", "A256GCM", publicKey, walletNonce, verifierNonce)
        
        val exception = assertFailsWith<OpenID4VPExceptions.UnsupportedOperationException> {
            handler.generateEncryptedResponse(payload)
        }
        
        val expectedMessage = "Unsupported encryption configuration: keyEncryptionAlgorithm=RSA-OAEP, contentEncryptionAlgorithm=A256GCM. Supported configuration: keyEncryptionAlgorithm=ECDH-ES, contentEncryptionAlgorithm=A256GCM"
        assertTrue(exception.message.contains(expectedMessage))
    }

    @Test
    fun `should throw UnsupportedOperationException when contentEncryptionAlg is unsupported`() {
        val payload = mapOf("key1" to "value1")
        val handler = JWEHandler(ECDH_ES, "A128GCM", publicKey, walletNonce, verifierNonce)
        
        val exception = assertFailsWith<OpenID4VPExceptions.UnsupportedOperationException> {
            handler.generateEncryptedResponse(payload)
        }
        
        val expectedMessage = "Unsupported encryption configuration: keyEncryptionAlgorithm=ECDH-ES, contentEncryptionAlgorithm=A128GCM. Supported configuration: keyEncryptionAlgorithm=ECDH-ES, contentEncryptionAlgorithm=A256GCM"
        assertTrue(exception.message.contains(expectedMessage))
    }
}

