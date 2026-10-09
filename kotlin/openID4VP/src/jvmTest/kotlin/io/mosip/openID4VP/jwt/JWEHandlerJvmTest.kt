package io.mosip.openID4VP.jwt

import io.mockk.clearAllMocks
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadataDraft23
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadataDraft23Serializer
import io.mosip.openID4VP.authorizationRequest.clientMetadata.Jwk
import io.mosip.openID4VP.authorizationRequest.deserializeAndValidate
import io.mosip.openID4VP.common.convertJsonToMap
import io.mosip.openID4VP.common.decodeFromBase64Url
import io.mosip.openID4VP.jwt.jwe.JWEHandler
import io.mosip.openID4VP.testData.clientMetadataString
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.*

class JWEHandlerJvmTest {
    private lateinit var clientMetadata: ClientMetadataDraft23
    private lateinit var jweHandler: JWEHandler
    private lateinit var publicKey: Jwk
    private val walletNonce = "d2FsbGV0Tm9uY2UxMjM" // "walletNonce123" base64url
    private val verifierNonce = "dmVyaWZpZXJOb25jZTQ1Ng" // "verifierNonce456" base64url

    @BeforeTest
    fun setUp() {
        clientMetadata = deserializeAndValidate(clientMetadataString, ClientMetadataDraft23Serializer)
        publicKey = clientMetadata.jwks!!.keys[1]
        jweHandler = JWEHandler(
            clientMetadata.authorizationEncryptedResponseAlg!!,
            clientMetadata.authorizationEncryptedResponseEnc!!,
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
    fun `should contain all the headers parameters of JWE successfully`() {
        val payload = mapOf("key1" to "value1", "key2" to 123)

        val encryptedResponse = jweHandler.generateEncryptedResponse(payload)

        assertNotNull(encryptedResponse)
        assert(encryptedResponse.isNotEmpty())
        val jweParts = encryptedResponse.split(".")
        assertEquals(5, jweParts.size)

        val decodedJWEHeader = convertJsonToMap(String(decodeFromBase64Url(jweParts[0]))).toMap()

        assertEquals(walletNonce, decodedJWEHeader["apu"])
        assertEquals(verifierNonce, decodedJWEHeader["apv"])
        assertEquals(publicKey.kid, decodedJWEHeader["kid"])
        assertEquals("ECDH-ES", decodedJWEHeader["alg"])
        assertEquals("A256GCM", decodedJWEHeader["enc"])
        assertEquals("OKP", (decodedJWEHeader["epk"] as Map<*, *>)["kty"])
        assertEquals("X25519", (decodedJWEHeader["epk"] as Map<*, *>)["crv"])
    }

}
