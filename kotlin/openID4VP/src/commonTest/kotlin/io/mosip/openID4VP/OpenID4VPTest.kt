package io.mosip.openID4VP

import io.mosip.openID4VP.common.encodeToBase64Url
import io.mosip.openID4VP.common.decodeFromBase64Url
import io.mosip.openID4VP.common.OpenID4VPErrorCodes
import io.mosip.openID4VP.common.OpenID4VPErrorFields.ERROR
import io.mosip.openID4VP.common.OpenID4VPErrorFields.ERROR_DESCRIPTION
import foundation.identity.jsonld.JsonLDObject
import io.mockk.*
import io.mosip.openID4VP.authorizationRequest.AuthorizationDcqlRequest
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationRequest.Verifier
import io.mosip.openID4VP.dcql.query.CredentialQuery
import io.mosip.openID4VP.dcql.query.DCQLQuery
import io.mosip.openID4VP.authorizationResponse.AuthorizationResponseHandler
import io.mosip.openID4VP.authorizationResponse.CredentialInputDescriptorMapping
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken
import io.mosip.openID4VP.verifier.VerifierResponse
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp.UnsignedLdpVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.mdoc.UnsignedMdocVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.VPTokenSigningResult
import io.mosip.openID4VP.common.URDNA2015Canonicalization
import io.mosip.openID4VP.common.UUIDGenerator
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.wallet.Credential
import io.mosip.openID4VP.constants.FormatType.LDP_VC
import io.mosip.openID4VP.constants.FormatType.MSO_MDOC
import io.mosip.openID4VP.constants.HttpMethod
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions.*
import io.mosip.openID4VP.networkManager.NetworkManagerClient
import io.mosip.openID4VP.networkManager.NetworkResponse
import io.mosip.openID4VP.testData.*
import org.junit.Test
import org.junit.jupiter.api.assertThrows
import kotlin.collections.mapOf
import kotlin.test.*

private const val OPENID_VC_REQUEST_URL = "openid-vc://?request=test-request"
private const val MOCK_VERIFIER_RESPONSE_URI = "https://mock-verifier.com/response-uri"
private const val VERIFIER_ENV2_RESPONSE_URI = "https://verifier.env2.com/responseUri"
private const val ERROR_RECEIVED_RESPONSE_BODY = """{"message":"Error received successfully"}"""
private const val CONTENT_TYPE_HEADER = "Content-Type"
private const val APPLICATION_JSON = "application/json"
private const val UNSUPPORTED_RESPONSE_MODE_MESSAGE = "Unsupported response_mode"
private const val RANDOM_UUID = "random-uuid"

class OpenID4VPTest {

    private lateinit var openID4VP: OpenID4VP
    private val selectedLdpCredentialsList = mapOf(
        "456" to listOf(
            Credential(LDP_VC, ldpCredential1, "456"),
            Credential(LDP_VC, ldpCredential2, "456")
        ), "789" to listOf(
            Credential(LDP_VC, ldpCredential2, "789")
        )
    )
    private val selectedMdocCredentialsList = mapOf(
        "123" to listOf(
            Credential(MSO_MDOC, mdocCredential, "123")
        )
    )

    @BeforeTest
    fun setUp() {
        mockkStatic("io.mosip.openID4VP.common.EncoderKt")
        every { encodeToBase64Url(any()) } answers { java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(firstArg()) }
        mockkStatic("io.mosip.openID4VP.common.DecoderKt")
        every { decodeFromBase64Url(any()) } answers { java.util.Base64.getUrlDecoder().decode(firstArg<String>()) }
        mockkObject(NetworkManagerClient)
        mockkObject(AuthorizationRequest)
        openID4VP = OpenID4VP("test-OpenID4VP")
        openID4VP.authorizationRequest = authorizationPresentationExchangeRequest
        setField(openID4VP, "responseDispatchInfo", testDispatchInfo(responseUrl))
        setField(openID4VP, "walletNonce", "bMHvX1HGhbh8zqlSWf/fuQ==")
    }

    @AfterTest
    fun tearDown() {
        clearAllMocks()
    }

    @Test
    fun `should authenticate verifier successfully`() {
        mockkObject(AuthorizationRequest)

        every {
            AuthorizationRequest.validateAndCreateAuthorizationRequest(
                any<String>(), any(), any(), any()
            )
        } returns authorizationPresentationExchangeRequest

        val result = openID4VP.authenticateVerifier(
            OPENID_VC_REQUEST_URL
        )

        assertEquals(authorizationPresentationExchangeRequest, result)
        verify {
            AuthorizationRequest.validateAndCreateAuthorizationRequest(
                OPENID_VC_REQUEST_URL,
                any(),
                any(),
                any()
            )
        }
    }

    @Test
    fun `should authenticate verifier successfully for pre-registered verifier with client metadata`() {
        mockkObject(AuthorizationRequest)

        every {
            AuthorizationRequest.validateAndCreateAuthorizationRequest(
                any<String>(), any(), any(), any()
            )
        } returns authorizationPresentationExchangeRequest
        val trustedVerifiers: List<Verifier> = listOf(
            Verifier(
                "mock-client", listOf(
                    MOCK_VERIFIER_RESPONSE_URI, VERIFIER_ENV2_RESPONSE_URI
                )
            ), Verifier(
                "mock-client2", listOf(
                    "https://verifier.env3.com/responseUri", VERIFIER_ENV2_RESPONSE_URI
                )
            )
        )

        val result = openID4VP.authenticateVerifier(
            OPENID_VC_REQUEST_URL
        )

        assertEquals(authorizationPresentationExchangeRequest, result)
        verify {
            AuthorizationRequest.validateAndCreateAuthorizationRequest(
                OPENID_VC_REQUEST_URL,
                any(),
                any(),
                any()
            )
        }
    }

    @Test
    fun `should throw exception during verifier authentication`() {
        mockkObject(AuthorizationRequest)
        mockkObject(NetworkManagerClient)

        var openID4VP = OpenID4VP("test-OpenID4VP")

        val testException = InvalidInput("", "Invalid authorization request","")

        every {
            AuthorizationRequest.validateAndCreateAuthorizationRequest(
                any<String>(), any(), any(), any()
            )
        } throws testException

        every {
            NetworkManagerClient.sendHTTPRequest(
                any(), any(), any()
            )
        } returns NetworkResponse(200, ERROR_RECEIVED_RESPONSE_BODY, mapOf(CONTENT_TYPE_HEADER to listOf(APPLICATION_JSON)))

        val invalidInputException = assertFailsWith<InvalidInput> {
            openID4VP.authenticateVerifier("openid-vc://?request=invalid")
        }

        assertOpenId4VPException(
            exception = invalidInputException,
            expectedMessage = "Invalid Input:  value cannot be empty or null",
            expectedErrorCode = "invalid_request",
            expectedVerifierResponse = null
        )
    }

    @Test
    fun `exception thrown should have verifier response if sent to verifier`() {
        val openID4VPInstance = OpenID4VP("OVPTest")
        mockkConstructor(AuthorizationResponseHandler::class)
        setField(openID4VPInstance, "responseDispatchInfo", testDispatchInfo(MOCK_VERIFIER_RESPONSE_URI))
        every {
            anyConstructed<AuthorizationResponseHandler>().sendAuthorizationError(
                any(),
                any(),
                any()
            )
        } returns VerifierResponse(200, null,ERROR_RECEIVED_RESPONSE_BODY, mapOf(CONTENT_TYPE_HEADER to listOf(APPLICATION_JSON)))

        val testException = InvalidInput("", "Invalid authorization request", "")
        every {
            AuthorizationRequest.validateAndCreateAuthorizationRequest(
                any<String>(), any(), any(), any()
            )
        } throws testException

        val exception = assertFailsWith<InvalidInput> {
            openID4VPInstance.authenticateVerifier("encodedAuthorizationRequest")
        }
        assertOpenId4VPException(
            exception = exception,
            expectedMessage = "Invalid Input:  value cannot be empty or null",
            expectedErrorCode = "invalid_request",
            expectedVerifierResponse = """VerifierResponse(statusCode=200, redirectUri=null, additionalParams={"message":"Error received successfully"}, headers={Content-Type=[application/json]})"""
        )
    }

    @Test
    fun `should construct unsigned VP token successfully`() {
        mockkObject(UUIDGenerator)
        mockkObject(URDNA2015Canonicalization)
        mockkStatic(JsonLDObject::class)

        every { UUIDGenerator.generateUUID() } returns "test-uuid-123"
        every { URDNA2015Canonicalization.canonicalize(any()) } returns "base64EncodedCanonicalisedData"
        every { JsonLDObject.fromJson(any<String>()) } returns JsonLDObject()

        mockkConstructor(UnsignedLdpVPTokenBuilder::class)
        every { anyConstructed<UnsignedLdpVPTokenBuilder>().build(any<List<CredentialInputDescriptorMapping>>()) } returns Pair(
            vpTokenSigningPayload,
            unsignedLdpVPToken
        )

        mockkConstructor(UnsignedMdocVPTokenBuilder::class)
        every { anyConstructed<UnsignedMdocVPTokenBuilder>().build(any<List<CredentialInputDescriptorMapping>>()) } returns Pair(
            emptyMap<String, ByteArray>(),
            unsignedMdocVPToken
        )

        val actualUnsignedVPTokens = openID4VP.constructUnsignedVPToken(
            selectedLdpCredentialsList
        )

        assertTrue(actualUnsignedVPTokens.isNotEmpty())
    }

    @Test
    fun `should throw exception during VP token construction with invalid data`() {
        val mockHandler = mockk<AuthorizationResponseHandler>()
        val testException = InvalidData("Invalid credential format","")

        every {
            mockHandler.constructUnsignedVPToken(any(), any(), any(), any())
        } throws testException

        setField(openID4VP, "authorizationResponseHandler", mockHandler)
        setField(openID4VP, "walletNonce", "bMHvX1HGhbh8zqlSWf/fuQ==")

        every {
            NetworkManagerClient.sendHTTPRequest(any(), any(), any(), any())
        } returns NetworkResponse(200, ERROR_RECEIVED_RESPONSE_BODY, mapOf(CONTENT_TYPE_HEADER to listOf(APPLICATION_JSON)))

        val thrown = assertFailsWith<InvalidData> {
            openID4VP.constructUnsignedVPToken(selectedLdpCredentialsList)
        }
        assertEquals("Invalid credential format", thrown.message)
    }

    @Test
    fun `should send error to verifier successfully`() {
        every {
            NetworkManagerClient.sendHTTPRequest(
                MOCK_VERIFIER_RESPONSE_URI,
                HttpMethod.POST,
                any(),
                any()
            )
        } returns NetworkResponse(200, """{"message":"VP share success"}""", mapOf(CONTENT_TYPE_HEADER to listOf(APPLICATION_JSON)))
        setField(openID4VP, "responseDispatchInfo", testDispatchInfo(MOCK_VERIFIER_RESPONSE_URI))

        val dispatchResult =
            openID4VP.sendErrorInfoToVerifier(InvalidData(UNSUPPORTED_RESPONSE_MODE_MESSAGE, ""))

        verify {
            NetworkManagerClient.sendHTTPRequest(
                MOCK_VERIFIER_RESPONSE_URI,
                HttpMethod.POST,
                match {
                    it["error"] == "invalid_request" &&
                            it["error_description"] == UNSUPPORTED_RESPONSE_MODE_MESSAGE
                },
                any()
            )
        }
        assertEquals("{\"message\":\"VP share success\"}", dispatchResult.additionalParams)
    }

    @Test
    fun `should send server_error to verifier when VP construction fails`() {
        val mockHandler = mockk<AuthorizationResponseHandler>()
        val innerException = InvalidData("Remote context loading issue", "")

        every {
            mockHandler.constructUnsignedVPToken(any(), any(), any(), any())
        } throws OpenID4VPExceptions.VerifiablePresentationConstructionFailure(innerException, "")

        setField(openID4VP, "authorizationResponseHandler", mockHandler)

        every {
            mockHandler.sendAuthorizationError(any(), any(), any())
        } returns VerifierResponse(200, null, ERROR_RECEIVED_RESPONSE_BODY, mapOf(CONTENT_TYPE_HEADER to listOf(APPLICATION_JSON)))

        val thrown = assertFailsWith<OpenID4VPExceptions.VerifiablePresentationConstructionFailure> {
            openID4VP.constructUnsignedVPToken(selectedLdpCredentialsList)
        }

        assertEquals("server_error", thrown.errorCode)
        assertEquals("The wallet encountered an internal error while preparing the presentation.", thrown.message)
        val cause = assertIs<InvalidData>(thrown.cause)
        assertEquals("Remote context loading issue", cause.message)
    }

    @Test
    fun `should throw exception during sending error to verifier if any error occurs during the process`() {
        every {
            NetworkManagerClient.sendHTTPRequest(any(), any(), any(), any())
        } throws Exception("Network error")


        val errorDispatchFailure = assertFailsWith<ErrorDispatchFailure> {
            openID4VP.sendErrorInfoToVerifier(Exception("Network error"))
        }

        assertOpenId4VPException(
            errorDispatchFailure,
            "Failed to send error to verifier: Failed to send error to verifier: Network error",
            "error_dispatch_failure"
        )
    }

    @Test
    fun `should throw exception during sending error to verifier when the response uri is not available`() {
        setField(openID4VP, "responseDispatchInfo", null)

        val errorDispatchFailure: ErrorDispatchFailure = assertThrows<ErrorDispatchFailure> {
            openID4VP.sendErrorInfoToVerifier(AccessDenied("Access denied by user", "OpenID4VPTest"))
        }

        assertOpenId4VPException(
            exception = errorDispatchFailure,
            expectedMessage = "Failed to send error to verifier: Response dispatch details are not set. Cannot send error to verifier.",
            expectedErrorCode = "error_dispatch_failure"
        )
    }

    @Test
    fun `should handle constructUnsignedVPToken with single format`() {
        val mockHandler = mockk<AuthorizationResponseHandler>()

        every {
            mockHandler.constructUnsignedVPToken(any(), any(), any(), any())
        } returns listOf(UnsignedVPToken(
            RANDOM_UUID,
            FormatType.LDP_VC,
            "keyRef",
            "Ed25519",
            "dataToSign".toByteArray()
        ))

        setField(openID4VP, "authorizationResponseHandler", mockHandler)

        val result = openID4VP.constructUnsignedVPToken(selectedLdpCredentialsList)

        assertEquals(1, result.size)
        assertEquals(FormatType.LDP_VC, result[0].format)
    }

    @Test
    fun `should handle sendVPResponseToVerifier method`() {
        val mockHandler = mockk<AuthorizationResponseHandler>()
        val vpTokenSigningResults = listOf(VPTokenSigningResult(
            id = RANDOM_UUID,
            signedData = "signedData".toByteArray()
        ))

        val redirectUri = "https://mock-verifier/com/redirect#response_code=jerhwf"
        every {
            mockHandler.constructAndSendAuthorizationResponseToVerifier(any(), any(), any())
        } returns VerifierResponse(200, redirectUri, """{"message":"success"}""", mapOf(CONTENT_TYPE_HEADER to listOf(APPLICATION_JSON)))

        setField(openID4VP, "authorizationResponseHandler", mockHandler)

        val result = openID4VP.sendVPResponseToVerifier(vpTokenSigningResults)

        assertEquals("{\"message\":\"success\"}", result.additionalParams)
        assertEquals(redirectUri, result.redirectUri)
    }

    @Test
    fun `should share the verifier response successfully on sending authorization response`() {
        val mockHandler = mockk<AuthorizationResponseHandler>()

        every {
            mockHandler.constructAndSendAuthorizationResponseToVerifier(any(), any(), any())
        } returns VerifierResponse(200, null, """{"message":"success"}""", mapOf(CONTENT_TYPE_HEADER to listOf(APPLICATION_JSON)))

        setField(openID4VP, "authorizationResponseHandler", mockHandler)

        val result = openID4VP.sendVPResponseToVerifier(listOf(VPTokenSigningResult(
            id = RANDOM_UUID,
            signedData = "signedMdocData".toByteArray()
        )))

        assertEquals("VerifierResponse(statusCode=200, redirectUri=null, additionalParams={\"message\":\"success\"}, headers={Content-Type=[application/json]})", result.toString())
    }

    @Test
    fun `should handle sendVPResponseToVerifier with mock response`() {
        val mockHandler = mockk<AuthorizationResponseHandler>()
        val vpTokenSigningResults = listOf(VPTokenSigningResult(
            id = RANDOM_UUID,
            signedData = "signedData".toByteArray()
        ))

        every {
            mockHandler.constructAndSendAuthorizationResponseToVerifier(any(), any(), any())
        } returns VerifierResponse(200, null, """{"status":"ok"}""", mapOf(CONTENT_TYPE_HEADER to listOf(APPLICATION_JSON)))

        setField(openID4VP, "authorizationResponseHandler", mockHandler)

        val result = openID4VP.sendVPResponseToVerifier(vpTokenSigningResults)

        assertEquals("{\"status\":\"ok\"}", result.additionalParams)
    }

    @Test
    fun `should handle exception in constructUnsignedVPToken method`() {
        val mockHandler = mockk<AuthorizationResponseHandler>()
        val exception = InvalidData("Invalid VC format","")

        every {
            mockHandler.constructUnsignedVPToken(any(), any(), any(), any())
        } throws exception

        every {
            NetworkManagerClient.sendHTTPRequest(any(), any(), any(), any())
        } returns NetworkResponse(200, ERROR_RECEIVED_RESPONSE_BODY, mapOf(CONTENT_TYPE_HEADER to listOf(APPLICATION_JSON)))

        setField(openID4VP, "authorizationResponseHandler", mockHandler)

        val thrown = assertFailsWith<InvalidData> {
            openID4VP.constructUnsignedVPToken(selectedLdpCredentialsList)
        }
        assertEquals("Invalid VC format", thrown.message)
    }

    @Test
    fun `should handle empty credential list`() {
        mockkObject(UUIDGenerator)
        every { UUIDGenerator.generateUUID() } returns "test-uuid-123"

        val mockHandler = mockk<AuthorizationResponseHandler>()
        every {
            mockHandler.constructUnsignedVPToken(any(), any(), any(), any())
        } returns emptyList()

        setField(openID4VP, "authorizationResponseHandler", mockHandler)

        val result = openID4VP.constructUnsignedVPToken(emptyMap())

        assertTrue(result.isEmpty())
    }

    @Test
    fun `should include state when sending error to verifier`() {
        every {
            NetworkManagerClient.sendHTTPRequest(
                MOCK_VERIFIER_RESPONSE_URI,
                HttpMethod.POST,
                any(),
                any()
            )
        } returns NetworkResponse(200, ERROR_RECEIVED_RESPONSE_BODY, mapOf(CONTENT_TYPE_HEADER to listOf(APPLICATION_JSON)))

        val customAuthorizationRequest = createAuthorizationRequestWithState("test-state")
        setField(openID4VP, "authorizationRequest", customAuthorizationRequest)
        setField(openID4VP, "responseDispatchInfo", testDispatchInfo(responseUrl, state = "test-state"))

        openID4VP.sendErrorInfoToVerifier(InvalidData("With state test", ""))

        verify {
            NetworkManagerClient.sendHTTPRequest(
                MOCK_VERIFIER_RESPONSE_URI,
                HttpMethod.POST,
                match {
                    it["error"] == "invalid_request" &&
                            it["error_description"] == "With state test" &&
                            it["state"] == "test-state"
                },
                any()
            )
        }
    }

    @Test
    fun `should not include state when authorization request has empty state`() {
        every {
            NetworkManagerClient.sendHTTPRequest(
                MOCK_VERIFIER_RESPONSE_URI,
                HttpMethod.POST,
                any(),
                any()
            )
        } returns NetworkResponse(200, ERROR_RECEIVED_RESPONSE_BODY, mapOf(CONTENT_TYPE_HEADER to listOf(APPLICATION_JSON)))

        val customAuthorizationRequest = createAuthorizationRequestWithState("")
        setField(openID4VP, "authorizationRequest", customAuthorizationRequest)
        setField(openID4VP, "responseDispatchInfo", testDispatchInfo(responseUrl, state = ""))

        openID4VP.sendErrorInfoToVerifier(InvalidData("empty state test", ""))

        verify {
            NetworkManagerClient.sendHTTPRequest(
                MOCK_VERIFIER_RESPONSE_URI,
                HttpMethod.POST,
                match {
                    it["error"] == "invalid_request" &&
                            it["error_description"] == "empty state test" &&
                            !it.containsKey("state")
                },
                any()
            )
        }
    }

    @Test
    fun `should not include state when authorization request has no state`() {
        every {
            NetworkManagerClient.sendHTTPRequest(
                MOCK_VERIFIER_RESPONSE_URI,
                HttpMethod.POST,
                any(),
                any()
            )
        } returns NetworkResponse(200, ERROR_RECEIVED_RESPONSE_BODY, mapOf(CONTENT_TYPE_HEADER to listOf(APPLICATION_JSON)))

        val noStateAuthorizationRequest = createAuthorizationRequestWithState(null)
        setField(openID4VP, "authorizationRequest", noStateAuthorizationRequest)
        setField(openID4VP, "responseDispatchInfo", testDispatchInfo(responseUrl, state = null))

        openID4VP.sendErrorInfoToVerifier(InvalidData("No state test", ""))

        verify {
            NetworkManagerClient.sendHTTPRequest(
                MOCK_VERIFIER_RESPONSE_URI,
                HttpMethod.POST,
                match {
                    it["error"] == "invalid_request" &&
                            it["error_description"] == "No state test" &&
                            !it.containsKey("state")
                },
                any()
            )
        }
    }

    @Test
    fun `should authenticate verifier successfully when auth request is of type Map`() {
        mockkObject(AuthorizationRequest)
        val authRequest = mapOf(
            "response_type" to "vp_token",
            "response_mode" to "iar-post",
            "presentation_definition" to mapOf(
                "id" to "vp token example",
                "purpose" to "Relying party is requesting your digital ID for the purpose of Self-Authentication",
                "format" to mapOf(
                    "ldp_vc" to mapOf(
                        "proof_type" to listOf("RsaSignature2018")
                    )
                ),
                "input_descriptors" to listOf(
                    mapOf(
                        "id" to "id card credential",
                        "format" to mapOf(
                            "ldp_vc" to mapOf(
                                "proof_type" to listOf("Ed25519Signature2020", "RsaSignature2018")
                            )
                        ),
                        "constraints" to mapOf(
                            "fields" to listOf(
                                mapOf(
                                    "path" to listOf("$.credentialSubject.email"),
                                    "filter" to mapOf(
                                        "type" to "string",
                                        "pattern" to "@gmail.com"
                                    )
                                )
                            )
                        )
                    )
                )
            ),
            "client_id" to "redirect_uri:https://example.com/iar/callback",
            "response_uri" to "https://example.com/iar/callback",
            "nonce" to "wiuegqgd"
        )


        every {
            AuthorizationRequest.validateAndCreateAuthorizationRequest(
                any<String>(), any(), any(), any()
            )
        } returns authorizationPresentationExchangeRequest
        val trustedVerifiers: List<Verifier> = listOf(
            Verifier(
                "mock-client", listOf(
                    MOCK_VERIFIER_RESPONSE_URI,
                    VERIFIER_ENV2_RESPONSE_URI
                )
            ), Verifier(
                "mock-client2", listOf(
                    "https://verifier.env3.com/responseUri",VERIFIER_ENV2_RESPONSE_URI
                )
            )
        )

        openID4VP.authenticateVerifier(
            authorizationRequest = authRequest
        )

        verify {
            AuthorizationRequest.validateAndCreateAuthorizationRequest(
                authRequest,
                any(),
                any(),
                any()
            )
        }
    }

    @Test
    fun `should handle constructVPToken method`() {
        val mockHandler = mockk<AuthorizationResponseHandler>()
        val vpTokenSigningResults = listOf(VPTokenSigningResult(
            id = RANDOM_UUID,
            signedData = "signedData".toByteArray()
        ))

        every {
            mockHandler.constructVPResponse(any(), any(), any())
        } returns mapOf("vp_token" to "<VP>", "presentation_submission" to "<Submission>")

        setField(openID4VP, "authorizationResponseHandler", mockHandler)

        val result = openID4VP.constructVPResponse(vpTokenSigningResults)

        assertEquals(mapOf("vp_token" to "<VP>", "presentation_submission" to "<Submission>"), result)
    }

    @Test
    fun `should construct error response successfully`() {
        setField(openID4VP, "walletNonce", "iqweutiuq3o4eq-")
        setField(openID4VP, "responseDispatchInfo", testDispatchInfo(MOCK_VERIFIER_RESPONSE_URI))
        val mockHandler = mockk<AuthorizationResponseHandler>()
        setField(openID4VP, "authorizationResponseHandler", mockHandler)
        every {
            mockHandler.constructAuthorizationErrorResponse(any(), any(), any(), any())
        } returns mapOf("error" to "invalid_request", "error_description" to UNSUPPORTED_RESPONSE_MODE_MESSAGE)

        val errorResult =
            openID4VP.constructErrorInfo(InvalidData(UNSUPPORTED_RESPONSE_MODE_MESSAGE, ""))


        assertEquals(mapOf("error" to "invalid_request", "error_description" to UNSUPPORTED_RESPONSE_MODE_MESSAGE), errorResult)
    }

    @Test
    fun `should construct unsigned VP token for DCQL requests`() {
        val mockHandler = mockk<AuthorizationResponseHandler>()
        val dcqlRequest = createDcqlAuthorizationRequest()
        val selectedCredentials = mapOf(
            "query-sdjwt" to listOf(Credential(FormatType.VC_SD_JWT, sdJwtCredential1, "credential-1"))
        )
        every {
            mockHandler.constructUnsignedVPToken(selectedCredentials, dcqlRequest, responseUrl, any())
        } returns unsignedSdJwtVPToken.take(1)

        setField(openID4VP, "authorizationRequest", dcqlRequest)
        setField(openID4VP, "authorizationResponseHandler", mockHandler)

        val result = openID4VP.constructUnsignedVPToken(selectedCredentials)

        assertEquals(unsignedSdJwtVPToken.take(1), result)
    }

    private fun newOpenID4VP() = OpenID4VP(traceabilityId = "trace-1")

    private fun newOpenID4VPWithDispatchInfo() = newOpenID4VP().apply {
        setField(this, "responseDispatchInfo", testDispatchInfo())
    }

    @Test
    fun `constructVPResponse returns error info when no authorization request was validated`() {
        val response = newOpenID4VPWithDispatchInfo().constructVPResponse(emptyList())

        assertEquals(OpenID4VPErrorCodes.SERVER_ERROR, response[ERROR])
        assertEquals(
            "The wallet encountered an internal error while preparing the authorization response.",
            response[ERROR_DESCRIPTION]
        )
    }

    @Test
    fun `constructUnsignedVPToken fails when no authorization request was validated`() {
        val exception = assertFailsWith<OpenID4VPExceptions.VerifiablePresentationConstructionFailure> {
            newOpenID4VP().constructUnsignedVPToken(emptyMap())
        }

        assertOpenId4VPException(
            exception = exception,
            expectedMessage = "The wallet encountered an internal error while preparing the presentation.",
            expectedErrorCode = OpenID4VPErrorCodes.SERVER_ERROR
        )
    }

    @Test
    fun `sendVPResponseToVerifier fails when no authorization request was validated`() {
        val exception = assertFailsWith<OpenID4VPExceptions.AuthorizationResponseConstructionFailure> {
            newOpenID4VP().sendVPResponseToVerifier(emptyList())
        }

        assertOpenId4VPException(
            exception = exception,
            expectedMessage = "The wallet encountered an internal error while preparing the authorization response.",
            expectedErrorCode = OpenID4VPErrorCodes.SERVER_ERROR
        )
    }

    @Test
    fun `constructErrorInfo renders an OpenID4VP exception`() {
        val response = newOpenID4VPWithDispatchInfo().constructErrorInfo(
            OpenID4VPExceptions.InvalidVerifier("unknown client", "test")
        )

        assertEquals(OpenID4VPErrorCodes.INVALID_CLIENT, response[ERROR])
        assertEquals("unknown client", response[ERROR_DESCRIPTION])
    }

    @Test
    fun `constructErrorInfo wraps a non-OpenID4VP exception as a server error`() {
        val response = newOpenID4VPWithDispatchInfo().constructErrorInfo(RuntimeException("boom"))

        assertEquals(OpenID4VPErrorCodes.SERVER_ERROR, response[ERROR])
        assertEquals("boom", response[ERROR_DESCRIPTION])
    }

    @Test
    fun `constructErrorInfo falls back to a generic description for a message-less exception`() {
        val response = newOpenID4VPWithDispatchInfo().constructErrorInfo(RuntimeException())

        assertEquals(OpenID4VPErrorCodes.SERVER_ERROR, response[ERROR])
        assertEquals("Unknown internal error", response[ERROR_DESCRIPTION])
    }

    @Test
    fun `authenticateVerifier rejects an authorization request with no client_id`() {
        val exception = assertFailsWith<OpenID4VPExceptions> {
            newOpenID4VP().authenticateVerifier(mapOf("response_type" to "vp_token"))
        }

        assertOpenId4VPException(
            exception = exception,
            expectedMessage = "Missing Input: client_id param is required",
            expectedErrorCode = OpenID4VPErrorCodes.INVALID_REQUEST
        )
    }

    @Test
    fun `authenticateVerifier rejects an url encoded request with no query parameters`() {
        val exception = assertFailsWith<OpenID4VPExceptions> {
            newOpenID4VP().authenticateVerifier("openid4vp://authorize")
        }

        assertOpenId4VPException(
            exception = exception,
            expectedMessage = "Exception occurred when extracting the query params from Authorization Request : Exception occurred when extracting the query params from Authorization Request : No Query params in the URI",
            expectedErrorCode = OpenID4VPErrorCodes.INVALID_REQUEST
        )
    }

    private fun createDcqlAuthorizationRequest(): AuthorizationDcqlRequest {
        return AuthorizationDcqlRequest(
            clientId = clientId,
            responseType = "vp_token",
            responseMode = "direct_post",
            responseUri = responseUrl,
            redirectUri = null,
            nonce = verifierNonce,
            walletNonce = walletNonce,
            state = null,
            clientMetadata = null,
            dcqlQuery = DCQLQuery(
                credentials = listOf(
                    CredentialQuery(
                        id = "query-sdjwt",
                        format = FormatType.VC_SD_JWT.value,
                        requireCryptographicHolderBinding = false
                    )
                )
            )
        )
    }
}

