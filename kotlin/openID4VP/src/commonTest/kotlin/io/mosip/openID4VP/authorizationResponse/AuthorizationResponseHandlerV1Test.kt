package io.mosip.openID4VP.authorizationResponse

import io.mosip.openID4VP.common.encodeToBase64Url
import io.mosip.openID4VP.common.decodeFromBase64Url
import io.mockk.*
import io.mosip.openID4VP.OpenID4VP
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.networkManager.NetworkManagerClient
import io.mosip.openID4VP.testData.*
import io.mosip.openID4VP.verifier.VerifierResponse
import kotlin.test.*
private const val TEST_WALLET_NONCE = "test-wallet-nonce"
private const val INTERNAL_ERROR_MESSAGE =
    "The wallet encountered an internal error while preparing the authorization response."
/**
 * Tests for AuthorizationResponseHandler.kt changes from PR #111:
 * - constructUnsignedVPToken passes walletNonce
 * - constructVPResponse returns error map on failure instead of throwing
 * - sendVPResponseToVerifier returns VerifierResponse with redirect_uri
 * - constructErrorInfo produces spec-compliant structure
 */
class AuthorizationResponseHandlerV1Test {

    private lateinit var openID4VP: OpenID4VP

    @BeforeTest
    fun setUp() {
        mockkStatic("io.mosip.openID4VP.common.EncoderKt")
        every { encodeToBase64Url(any()) } answers { java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(firstArg()) }
        mockkStatic("io.mosip.openID4VP.common.DecoderKt")
        every { decodeFromBase64Url(any()) } answers { java.util.Base64.getUrlDecoder().decode(firstArg<String>()) }
        mockkObject(NetworkManagerClient)
        mockkObject(AuthorizationRequest)
        openID4VP = OpenID4VP("response-handler-v1-test")
        openID4VP.authorizationRequest = authorizationPresentationExchangeRequest
        setField(openID4VP, "responseDispatchInfo", testDispatchInfo(responseUrl))
        setField(openID4VP, "walletNonce", TEST_WALLET_NONCE)
    }

    @AfterTest
    fun tearDown() {
        clearAllMocks()
    }

    // --- constructUnsignedVPToken passes walletNonce ---

    @Test
    fun `constructUnsignedVPToken passes walletNonce for KB-JWT and proof challenge`() {
        val mockHandler = mockk<AuthorizationResponseHandler>()
        setField(openID4VP, "authorizationResponseHandler", mockHandler)

        every {
            mockHandler.constructUnsignedVPToken(any(), any(), any(), eq(TEST_WALLET_NONCE))
        } returns emptyList()

        openID4VP.constructUnsignedVPToken(emptyMap())

        verify {
            mockHandler.constructUnsignedVPToken(any(), any(), any(), eq(TEST_WALLET_NONCE))
        }
    }

    @Test
    fun `constructUnsignedVPToken sends error to verifier on OpenID4VPException`() {
        val mockHandler = mockk<AuthorizationResponseHandler>()
        setField(openID4VP, "authorizationResponseHandler", mockHandler)

        val innerException = OpenID4VPExceptions.InvalidData("No credentials", "test")
        every {
            mockHandler.constructUnsignedVPToken(any(), any(), any(), any())
        } throws OpenID4VPExceptions.VerifiablePresentationConstructionFailure(innerException, "test")

        every {
            mockHandler.sendAuthorizationError(any(), any(), any())
        } returns VerifierResponse(200, null, """{"ok":true}""", mapOf())

        val thrown = assertFailsWith<OpenID4VPExceptions.VerifiablePresentationConstructionFailure> {
            openID4VP.constructUnsignedVPToken(emptyMap())
        }
        assertEquals("server_error", thrown.errorCode)
        assertEquals("The wallet encountered an internal error while preparing the presentation.", thrown.message)
        val cause = assertIs<OpenID4VPExceptions.InvalidData>(thrown.cause)
        assertEquals("No credentials", cause.message)
    }

    // --- constructVPResponse error map fallback ---

    @Test
    fun `constructVPResponse returns server_error map on OpenID4VPExceptions instead of throwing`() {
        val mockHandler = mockk<AuthorizationResponseHandler>()
        setField(openID4VP, "authorizationResponseHandler", mockHandler)

        val innerException = OpenID4VPExceptions.InvalidData("bad signing result", "test")
        every {
            mockHandler.constructVPResponse(any(), any(), any())
        } throws OpenID4VPExceptions.AuthorizationResponseConstructionFailure(innerException, "test")

        val capturedEx = slot<Exception>()
        every {
            mockHandler.constructAuthorizationErrorResponse(any(), capture(capturedEx), any(), any())
        } returns mapOf("error" to "server_error", "error_description" to INTERNAL_ERROR_MESSAGE)

        val result = openID4VP.constructVPResponse(emptyList())

        assertEquals("server_error", result["error"])
        assertEquals(INTERNAL_ERROR_MESSAGE, result["error_description"])

        val capturedError = assertIs<OpenID4VPExceptions.AuthorizationResponseConstructionFailure>(capturedEx.captured)
        assertEquals("server_error", capturedError.errorCode)
        assertEquals(INTERNAL_ERROR_MESSAGE, capturedError.message)
        val cause = assertIs<OpenID4VPExceptions.InvalidData>(capturedError.cause)
        assertEquals("bad signing result", cause.message)
    }

    @Test
    fun `constructVPResponse returns vp_token and presentation_submission on success`() {
        val mockHandler = mockk<AuthorizationResponseHandler>()
        setField(openID4VP, "authorizationResponseHandler", mockHandler)

        every {
            mockHandler.constructVPResponse(any(), any(), any())
        } returns mapOf(
            "vp_token" to "signed-vp-token",
            "presentation_submission" to "{...}",
            "state" to "some-state"
        )

        val result = openID4VP.constructVPResponse(emptyList())

        assertTrue(result.containsKey("vp_token"))
        assertTrue(result.containsKey("presentation_submission"))
    }

    // --- sendVPResponseToVerifier ---

    @Test
    fun `sendVPResponseToVerifier returns VerifierResponse with redirect_uri`() {
        val mockHandler = mockk<AuthorizationResponseHandler>()
        setField(openID4VP, "authorizationResponseHandler", mockHandler)

        every {
            mockHandler.constructAndSendAuthorizationResponseToVerifier(any(), any(), any())
        } returns VerifierResponse(
            200,
            "https://verifier.com/redirect#response_code=abc",
            """{"transaction_id":"123"}""",
            mapOf("Content-Type" to listOf("application/json"))
        )

        val result = openID4VP.sendVPResponseToVerifier(emptyList())

        assertEquals(200, result.statusCode)
        assertEquals("https://verifier.com/redirect#response_code=abc", result.redirectUri)
        assertEquals("""{"transaction_id":"123"}""", result.additionalParams)
    }

    @Test
    fun `sendVPResponseToVerifier handles null redirect_uri from verifier`() {
        val mockHandler = mockk<AuthorizationResponseHandler>()
        setField(openID4VP, "authorizationResponseHandler", mockHandler)

        every {
            mockHandler.constructAndSendAuthorizationResponseToVerifier(any(), any(), any())
        } returns VerifierResponse(200, null, """{"tx_id":"abc"}""", mapOf())

        val result = openID4VP.sendVPResponseToVerifier(emptyList())

        assertNull(result.redirectUri)
        assertEquals("""{"tx_id":"abc"}""", result.additionalParams)
    }

    @Test
    fun `sendVPResponseToVerifier throws and sends server_error on failure`() {
        val mockHandler = mockk<AuthorizationResponseHandler>()
        setField(openID4VP, "authorizationResponseHandler", mockHandler)

        val innerException = OpenID4VPExceptions.InvalidData("VP token construction failed", "test")
        every {
            mockHandler.constructAndSendAuthorizationResponseToVerifier(any(), any(), any())
        } throws OpenID4VPExceptions.AuthorizationResponseConstructionFailure(innerException, "test")

        every {
            mockHandler.sendAuthorizationError(any(), any(), any())
        } returns VerifierResponse(200, null, """{"received":true}""", mapOf())

        val thrown = assertFailsWith<OpenID4VPExceptions.AuthorizationResponseConstructionFailure> {
            openID4VP.sendVPResponseToVerifier(emptyList())
        }
        assertEquals("server_error", thrown.errorCode)
        assertEquals(INTERNAL_ERROR_MESSAGE, thrown.message)
        val cause = assertIs<OpenID4VPExceptions.InvalidData>(thrown.cause)
        assertEquals("VP token construction failed", cause.message)

        assertNotNull(thrown.verifierResponse)
    }

    // --- constructErrorInfo ---

    @Test
    fun `constructErrorInfo produces spec-compliant error structure`() {
        val mockHandler = mockk<AuthorizationResponseHandler>()
        setField(openID4VP, "authorizationResponseHandler", mockHandler)

        every {
            mockHandler.constructAuthorizationErrorResponse(any(), any(), any(), any())
        } returns mapOf(
            "error" to "invalid_request",
            "error_description" to "Missing nonce",
            "state" to "test-state"
        )

        val result = openID4VP.constructErrorInfo(OpenID4VPExceptions.MissingInput("nonce", "", "test"))

        assertTrue(result.containsKey("error"))
        assertTrue(result.containsKey("error_description"))
    }
}

