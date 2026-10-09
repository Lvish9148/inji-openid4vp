package io.mosip.openID4VP.authorizationResponse

import foundation.identity.jsonld.JsonLDObject
import io.mockk.*
import io.mosip.openID4VP.authorizationRequest.AuthorizationDcqlRequest
import io.mosip.openID4VP.authorizationRequest.AuthorizationPresentationExchangeRequest
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationRequest.deserializeAndValidate
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.PresentationDefinitionSerializer
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.DescriptorMap
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.PathNested
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp.UnsignedLdpVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.mdoc.UnsignedMdocVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.sdJwt.UnsignedSdJwtVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.vpToken.VPTokenType
import io.mosip.openID4VP.authorizationResponse.vpToken.types.ldp.LdpVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.vpToken.types.mdoc.MdocVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.VPTokenSigningResult
import io.mosip.openID4VP.common.URDNA2015Canonicalization
import io.mosip.openID4VP.common.UUIDGenerator
import io.mosip.openID4VP.common.decodeFromBase64Url
import io.mosip.openID4VP.common.encodeToBase64Url
import io.mosip.openID4VP.common.resolveSdJwtKeyAndAlg
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.constants.FormatType.*
import io.mosip.openID4VP.dcql.query.CredentialQuery
import io.mosip.openID4VP.dcql.query.DCQLQuery
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions.*
import io.mosip.openID4VP.networkManager.NetworkManagerClient
import io.mosip.openID4VP.networkManager.NetworkResponse
import io.mosip.openID4VP.responseModeHandler.ResponseDispatchInfo
import io.mosip.openID4VP.responseModeHandler.ResponseEncryptionSpecification
import io.mosip.openID4VP.responseModeHandler.ResponseModeBasedHandler
import io.mosip.openID4VP.responseModeHandler.ResponseModeBasedHandlerFactory
import io.mosip.openID4VP.responseModeHandler.types.DirectPostResponseModeHandler
import io.mosip.openID4VP.testData.*
import io.mosip.openID4VP.wallet.Credential
import java.io.IOException
import java.util.Base64
import kotlin.test.*
private const val MDOC_CREDENTIAL_ID = "mdoc-1"
private const val VERIFIABLE_CREDENTIAL_PATH = "$.verifiableCredential[0]"
private const val LDP_CREDENTIAL_UUID = "ldp-uuid1"
private const val SUCCESS_RESPONSE_BODY = """{"message":"success"}"""
private const val MOCK_VERIFIER_URL = "https://mock-verifier.com"
private const val PRESENTATION_INTERNAL_ERROR_MESSAGE = "The wallet encountered an internal error while preparing the presentation."
private const val RANDOM_UUID = "random-uuid"
private const val MOCK_SIGNED_DATA = "mock-signed-data"
private const val AUTHORIZATION_RESPONSE_INTERNAL_ERROR_MESSAGE = "The wallet encountered an internal error while preparing the authorization response."
private const val MOCK_SIGNED_DATA_1 = "mock-signed-1"
private const val UUID_1 = "uuid-1"
private const val UUID_2 = "uuid-2"
private const val LDP_CREDENTIAL_UUID_2 = "ldp-uuid2"
private const val MDOC_CREDENTIAL_UUID_1 = "mdoc-uuid1"
private const val SD_JWT_CREDENTIAL_UUID_1 = "sd-jwt-uuid1"
private const val SD_JWT_CREDENTIAL_UUID_2 = "sd-jwt-uuid2"
private const val VERIFIER_CALLBACK_URI = "https://verifier.example.com/cb"
private const val INVALID_DATA_PROVIDED_MESSAGE = "Invalid data provided"
private const val WALLET_NONCE_VALUE = "wallet-nonce-value"
private const val TEST_STATE_VALUE = "test-state-value"
private const val QUERY_SDJWT = "query-sdjwt"
private const val QUERY_MDOC = "query-mdoc"
private const val CRED_1 = "cred-1"
private const val CRED_MDOC = "cred-mdoc"
private const val CRED_SDJWT = "cred-sdjwt"
private const val MOCK_SIG = "mock-sig"

class AuthorizationResponseHandlerTest {
    private val ldpVcList1 = listOf(ldpCredential1, ldpCredential2)
    private val ldpVcList2 = listOf(ldpCredential2)
    private val mdocVcList = listOf(mdocCredential)

    private val selectedLdpVcCredentialsList = mapOf(
        "456" to listOf(
            Credential(LDP_VC, ldpCredential1, "ldp-1"),
            Credential(LDP_VC, ldpCredential2, "ldp-2")
        ),
        "789" to listOf(Credential(LDP_VC, ldpCredential2, "ldp-2"))
    )
    private val selectedMdocCredentialsList = mapOf(
        "123" to listOf(Credential(MSO_MDOC, mdocCredential, MDOC_CREDENTIAL_ID))
    )

    private val selectedSdJwtCredentialsList = mapOf(
        "142" to listOf(Credential(VC_SD_JWT, sdJwtCredential1, "sdjwt-1"))
    )
    private val credentialsMap = mapOf(
        "input1" to listOf(Credential(LDP_VC, ldpCredential1, "ldp-1")),
        "input2" to listOf(Credential(MSO_MDOC, mdocCredential, MDOC_CREDENTIAL_ID))
    )

    private val credentialMap2 = mapOf(
        "input1" to listOf(
            Credential(LDP_VC, ldpCredential1, "ldp-1"),
            Credential(LDP_VC, ldpCredential2, "ldp-2")
        ),
        "input2" to listOf(Credential(MSO_MDOC, mdocCredential, MDOC_CREDENTIAL_ID)),
        "input3" to listOf(Credential(VC_SD_JWT, sdJwtCredential2, "sdjwt-2"))
    )

    private val unsignedKBJwt = "eyJhbGciOiJFUzI1NksifQ.eyJub25jZSI6Im5vbmNlIn0"

    private lateinit var authorizationResponseHandler: AuthorizationResponseHandler
    private val mockResponseHandler = mockk<ResponseModeBasedHandler>()

    private fun dispatchInfoFor(
        request: AuthorizationRequest = authorizationPresentationExchangeRequest,
        responseUrl: String = request.responseUri ?: "https://mock-verifier.com",
        encryptionSpecification: ResponseEncryptionSpecification? = null
    ) = ResponseDispatchInfo(
        responseMode = request.responseMode ?: "direct_post",
        nonce = request.nonce,
        walletNonce = request.walletNonce,
        state = request.state,
        clientId = request.clientId,
        responseUrl = responseUrl,
        responseEncryptionSpecification = encryptionSpecification
    )

    @BeforeTest
    fun setUp() {
        authorizationResponseHandler = AuthorizationResponseHandler(walletConfig)

        mockkStatic(::decodeFromBase64Url)
        every { decodeFromBase64Url(any()) } answers {
            Base64.getUrlDecoder().decode(firstArg<String>())
        }

        mockkConstructor(LdpVPTokenBuilder::class)
        every {
            anyConstructed<LdpVPTokenBuilder>().build(
                any(),
                any(),
                any(),
                any()
            )
        } returns Triple(
            listOf(ldpVPToken), listOf(
                DescriptorMap(
                    "input1",
                    "ldp_vp",
                    "$[2]",
                    PathNested("input1", "ldp_vc", VERIFIABLE_CREDENTIAL_PATH)
                ),
                DescriptorMap(
                    "input1",
                    "ldp_vp",
                    "$[2]",
                    PathNested("input1", "ldp_vc", "$.verifiableCredential[1]")
                )
            ),
            2
        )

        mockkConstructor(MdocVPTokenBuilder::class)
        every {
            anyConstructed<MdocVPTokenBuilder>().build(
                any(),
                any(),
                any(),
                any()
            )
        } returns Triple(
            listOf(mdocVPToken), listOf(), 0
        )

        // DCQL overload (3-arg) for MdocVPTokenBuilder
        every {
            anyConstructed<MdocVPTokenBuilder>().build(
                credentialToCredentialQueryIdMappings = any<List<CredentialToCredentialQueryIdMapping>>(),
                unsignedVPTokenResult = any(),
                vpTokenSigningResults = any()
            )
        } answers {
            val mappings = firstArg<List<CredentialToCredentialQueryIdMapping>>()
            mappings.associate { it.credentialQueryId to listOf(mdocVPToken) }
        }

        setField(
            authorizationResponseHandler,
            "formatToCredentialInputDescriptorMapping",
            mapOf(
                LDP_VC to listOf(
                    CredentialInputDescriptorMapping(LDP_VC, ldpCredential1, "456"),
                    CredentialInputDescriptorMapping(LDP_VC, ldpCredential2, "789"),
                )
            ) + mapOf(
                MSO_MDOC to listOf(
                    CredentialInputDescriptorMapping(
                        MSO_MDOC,
                        mdocVcList.first(),
                        "123"
                    ).apply { identifier = "org.iso.18013.5.1.mDL" }
                )
            )
        )
        setField(
            authorizationResponseHandler, "unsignedVPTokenResults", mapOf(
                LDP_VC to Pair(vpTokenSigningPayload, unsignedLdpVPToken),
                MSO_MDOC to Pair(mdocDocTypeToDeviceAuthBytes, unsignedMdocVPToken),
            )
        )
        setField(authorizationResponseHandler, "walletNonce", "bMHvX1HGhbh8zqlSWf/fuQ==")
        // signatureSuite field removed


        mockkObject(UUIDGenerator)
        every { UUIDGenerator.generateUUID() } returns "649d581c-f291-4969-9cd5-2c27385a348f"

        mockkObject(URDNA2015Canonicalization)
        mockkStatic(JsonLDObject::class)

        every { URDNA2015Canonicalization.canonicalize(any()) } returns "base64EncodedCanonicalisedData"
        every { JsonLDObject.fromJson(any<String>()) } returns JsonLDObject()

        mockkObject(NetworkManagerClient)

        mockkConstructor(UnsignedLdpVPTokenBuilder::class)
        every { anyConstructed<UnsignedLdpVPTokenBuilder>().build(any<List<CredentialInputDescriptorMapping>>()) } returns Pair(
            vpTokenSigningPayload, unsignedLdpVPToken
        )
        every { anyConstructed<UnsignedLdpVPTokenBuilder>().build(any<MutableList<CredentialToCredentialQueryIdMapping>>()) } returns Pair(
            mapOf(LDP_CREDENTIAL_UUID to ldpCredential1),
            unsignedLdpVPToken
        )

        mockkConstructor(UnsignedMdocVPTokenBuilder::class)
        every { anyConstructed<UnsignedMdocVPTokenBuilder>().build(any<List<CredentialInputDescriptorMapping>>()) } answers {
            val mappings = firstArg<List<CredentialInputDescriptorMapping>>()
            val docTypes = mdocDocTypeToDeviceAuthBytes.keys.toList()
            mappings.forEachIndexed { index, mapping ->
                if (index < docTypes.size) mapping.identifier = docTypes[index]
            }
            Pair(mdocDocTypeToDeviceAuthBytes, unsignedMdocVPToken)
        }
        every { anyConstructed<UnsignedMdocVPTokenBuilder>().build(any<MutableList<CredentialToCredentialQueryIdMapping>>()) } answers {
            val mappings = firstArg<MutableList<CredentialToCredentialQueryIdMapping>>()
            val docTypes = mdocDocTypeToDeviceAuthBytes.keys.toList()
            mappings.forEachIndexed { index, mapping ->
                if (index < docTypes.size) mapping.identifier = docTypes[index]
            }
            Pair(mdocDocTypeToDeviceAuthBytes, unsignedMdocVPToken)
        }

        mockkConstructor(UnsignedSdJwtVPTokenBuilder::class)
        every { anyConstructed<UnsignedSdJwtVPTokenBuilder>().build(any<List<CredentialInputDescriptorMapping>>()) } answers {
            val mappings = firstArg<List<CredentialInputDescriptorMapping>>()
            val allUuids = sdJwtIdToUnsignedKBJWT.keys.sorted()
            val uuidsToUse = allUuids.take(mappings.size)
            mappings.forEachIndexed { index, mapping ->
                if (index < uuidsToUse.size) mapping.identifier = uuidsToUse[index]
            }
            val filteredKBT: Map<String, String> =
                uuidsToUse.associateWith { sdJwtIdToUnsignedKBJWT[it]!! }
            val unsignedTokens = uuidsToUse.map { uuid ->
                UnsignedVPToken(
                    uuid,
                    VC_SD_JWT,
                    "kid-$uuid",
                    "ES256K",
                    filteredKBT[uuid]!!.toByteArray()
                )
            }
            Pair(filteredKBT, unsignedTokens)
        }

        mockkStatic("io.mosip.openID4VP.common.UtilsKt")
        every { resolveSdJwtKeyAndAlg(any(), any()) } returns ("did:key:mock#key-1" to "EdDSA")

        mockkStatic(::encodeToBase64Url)
        every { encodeToBase64Url(any()) } answers {
            val input = firstArg<ByteArray>()
            Base64.getUrlEncoder().withoutPadding().encodeToString(input)
        }

        mockkObject(ResponseModeBasedHandlerFactory)
        every { ResponseModeBasedHandlerFactory.get(any()) } returns mockResponseHandler
        every {
            mockResponseHandler.sendAuthorizationResponse(any(), any(), any())
        } returns NetworkResponse(200, SUCCESS_RESPONSE_BODY, mapOf())
        every {
            mockResponseHandler.sendAuthorizationError(any(), any(), any())
        } answers {
            DirectPostResponseModeHandler().sendAuthorizationError(firstArg(), secondArg(), thirdArg())
        }
    }

    @AfterTest
    fun tearDown() {
        clearAllMocks()
    }

    @Test
    fun `should successfully construct unsigned VP tokens for both LDP_VC and MSO_MDOC formats`() {
        val unsignedVPToken = authorizationResponseHandler.constructUnsignedVPToken(
            selectedCredentials = selectedMdocCredentialsList + selectedLdpVcCredentialsList,
            authorizationRequest = authorizationPresentationExchangeRequest,
            responseUri = MOCK_VERIFIER_URL,
            nonce = walletNonce
        )

        assertNotNull(unsignedVPToken)
        assertTrue(unsignedVPToken.isNotEmpty())
    }

    @Test
    fun `should successfully construct unsigned VP tokens for both LDP_VC, MSO_MDOC, SD_JWT formats`() {

        val authRequest = AuthorizationPresentationExchangeRequest(
            clientId = authorizationPresentationExchangeRequest.clientId,
            responseType = authorizationPresentationExchangeRequest.responseType,
            responseMode = authorizationPresentationExchangeRequest.responseMode,
            presentationDefinition = authorizationPresentationExchangeRequest.presentationDefinition,
            responseUri = authorizationPresentationExchangeRequest.responseUri,
            redirectUri = authorizationPresentationExchangeRequest.redirectUri,
            nonce = authorizationPresentationExchangeRequest.nonce,
            state = authorizationPresentationExchangeRequest.state,
            clientMetadata = authorizationPresentationExchangeRequest.clientMetadata,
            walletNonce = authorizationPresentationExchangeRequest.walletNonce
        )
        authRequest.presentationDefinition = deserializeAndValidate(
            presentationDefinitionMapWithSdJwt,
            PresentationDefinitionSerializer
        )
        val unsignedVPToken = authorizationResponseHandler.constructUnsignedVPToken(
            selectedCredentials = selectedMdocCredentialsList + selectedLdpVcCredentialsList + selectedSdJwtCredentialsList,
            authorizationRequest = authRequest,
            responseUri = MOCK_VERIFIER_URL,
            nonce = walletNonce
        )

        assertNotNull(unsignedVPToken)
        assertTrue(unsignedVPToken.isNotEmpty())
    }

    @Test
    fun `should throw error during construction of data for signing when selected Credentials is empty`() {
        val exception = assertFailsWith<VerifiablePresentationConstructionFailure> {
            authorizationResponseHandler.constructUnsignedVPToken(
                selectedCredentials = mapOf(),
                authorizationRequest = authorizationPresentationExchangeRequest,
                responseUri = MOCK_VERIFIER_URL,
                nonce = walletNonce
            )
        }
        assertEquals("server_error", exception.errorCode)
        assertEquals(
            PRESENTATION_INTERNAL_ERROR_MESSAGE,
            exception.message
        )
        val cause = assertIs<InvalidData>(exception.cause)
        assertEquals(
            "Empty credentials list - The Wallet did not have the requested Credentials to satisfy the Authorization Request.",
            cause.message
        )
    }

    @Test
    fun `should throw error when response type is not supported`() {
        val request = AuthorizationPresentationExchangeRequest(
            clientId = authorizationPresentationExchangeRequest.clientId,
            responseType = "code",
            responseMode = authorizationPresentationExchangeRequest.responseMode,
            presentationDefinition = authorizationPresentationExchangeRequest.presentationDefinition,
            responseUri = authorizationPresentationExchangeRequest.responseUri,
            redirectUri = authorizationPresentationExchangeRequest.redirectUri,
            nonce = authorizationPresentationExchangeRequest.nonce,
            state = authorizationPresentationExchangeRequest.state,
            clientMetadata = authorizationPresentationExchangeRequest.clientMetadata,
            walletNonce = authorizationPresentationExchangeRequest.walletNonce
        )
        val exception = assertFailsWith<AuthorizationResponseConstructionFailure> {
            authorizationResponseHandler.constructAndSendAuthorizationResponseToVerifier(
                authorizationRequest = request,
                vpTokenSigningResults = listOf(
                    VPTokenSigningResult(
                        id = RANDOM_UUID,
                        signedData = MOCK_SIGNED_DATA.toByteArray()
                    )
                ),
                dispatchInfo = dispatchInfoFor(request = request, responseUrl = authorizationPresentationExchangeRequest.responseUri!!)
            )
        }
        assertEquals("server_error", exception.errorCode)
        assertEquals(
            AUTHORIZATION_RESPONSE_INTERNAL_ERROR_MESSAGE,
            exception.message
        )
        val cause = assertIs<InvalidData>(exception.cause)
        assertEquals("Provided response_type - code is not supported", cause.message)
    }

    @Test
    fun `should throw error when a credential format entry is not available in unsignedVPTokens but available in vpTokenSigningResults`() {
        setField(
            authorizationResponseHandler,
            "unsignedVPTokenResults",
            emptyMap<FormatType, Pair<Any?, UnsignedVPToken>>()
        )
        setField(
            authorizationResponseHandler,
            "formatToCredentialInputDescriptorMapping",
            emptyMap<FormatType, List<CredentialInputDescriptorMapping>>()
        )

        val exception = assertFailsWith<AuthorizationResponseConstructionFailure> {
            authorizationResponseHandler.constructAndSendAuthorizationResponseToVerifier(
                authorizationRequest = authorizationPresentationExchangeRequest,
                vpTokenSigningResults = listOf(
                    VPTokenSigningResult(
                        id = RANDOM_UUID,
                        signedData = MOCK_SIGNED_DATA.toByteArray()
                    )
                ),
                dispatchInfo = dispatchInfoFor(request = authorizationPresentationExchangeRequest, responseUrl = authorizationPresentationExchangeRequest.responseUri!!)
            )
        }
        assertEquals("server_error", exception.errorCode)
        assertEquals(
            AUTHORIZATION_RESPONSE_INTERNAL_ERROR_MESSAGE,
            exception.message
        )
        val cause = assertIs<InvalidData>(exception.cause)
        assertEquals(
            "Unexpected VP token signing result for credential identifier(s): random-uuid",
            cause.message
        )
    }

    @Test
    fun `should throw exception when credentials map is empty`() {
        val exception = assertFailsWith<VerifiablePresentationConstructionFailure> {
            authorizationResponseHandler.constructUnsignedVPToken(
                selectedCredentials = emptyMap(),
                authorizationRequest = authorizationPresentationExchangeRequest,
                responseUri = responseUrl,
                nonce = walletNonce
            )
        }
        assertEquals("server_error", exception.errorCode)
        assertEquals(
            PRESENTATION_INTERNAL_ERROR_MESSAGE,
            exception.message
        )
        val cause = assertIs<InvalidData>(exception.cause)
        assertEquals(
            "Empty credentials list - The Wallet did not have the requested Credentials to satisfy the Authorization Request.",
            cause.message
        )
    }

    @Test
    fun `should successfully share VP with valid signing results`() {
        authorizationResponseHandler.constructUnsignedVPToken(
            selectedCredentials = credentialsMap,
            authorizationRequest = authorizationPresentationExchangeRequest,
            responseUri = responseUrl,
            nonce = walletNonce
        )

        val result = authorizationResponseHandler.constructAndSendAuthorizationResponseToVerifier(
            authorizationRequest = authorizationPresentationExchangeRequest,
            vpTokenSigningResults = listOf(
                VPTokenSigningResult(
                    id = RANDOM_UUID,
                    signedData = "mock-ldp-signed".toByteArray()
                )
            ),
            dispatchInfo = dispatchInfoFor(request = authorizationPresentationExchangeRequest, responseUrl = responseUrl)
        )

        assertEquals(SUCCESS_RESPONSE_BODY, result.additionalParams)

        verify {
            ResponseModeBasedHandlerFactory.get("direct_post")
            mockResponseHandler.sendAuthorizationResponse(
                dispatchInfo = any(),
                authorizationResponse = any(),
                authorizationRequest = authorizationPresentationExchangeRequest
            )
        }
    }

    @Test
    fun `should throw exception when response type is not supported`() {
        val mockInvalidRequest = mockk<AuthorizationRequest>()
        every { mockInvalidRequest.responseType } returns "code"

        // Populate internal state with valid input first
        authorizationResponseHandler.constructUnsignedVPToken(
            selectedCredentials = credentialsMap,
            authorizationRequest = authorizationPresentationExchangeRequest,
            responseUri = responseUrl,
            nonce = walletNonce
        )

        val exception = assertFailsWith<AuthorizationResponseConstructionFailure> {
            authorizationResponseHandler.constructAndSendAuthorizationResponseToVerifier(
                authorizationRequest = mockInvalidRequest,
                vpTokenSigningResults = listOf(
                    VPTokenSigningResult(
                        id = RANDOM_UUID,
                        signedData = MOCK_SIGNED_DATA.toByteArray()
                    )
                ),
                dispatchInfo = dispatchInfoFor(responseUrl = responseUrl)
            )
        }
        assertEquals("server_error", exception.errorCode)
        assertEquals(
            AUTHORIZATION_RESPONSE_INTERNAL_ERROR_MESSAGE,
            exception.message
        )
        val cause = assertIs<InvalidData>(exception.cause)
        assertEquals("Provided response_type - code is not supported", cause.message)
    }


    @Test
    fun `should throw exception when unsupported response mode is provided`() {
        val request = AuthorizationPresentationExchangeRequest(
            clientId = authorizationPresentationExchangeRequest.clientId,
            responseType = authorizationPresentationExchangeRequest.responseType,
            responseMode = "unsupported_mode",
            presentationDefinition = authorizationPresentationExchangeRequest.presentationDefinition,
            responseUri = authorizationPresentationExchangeRequest.responseUri,
            redirectUri = authorizationPresentationExchangeRequest.redirectUri,
            nonce = authorizationPresentationExchangeRequest.nonce,
            state = authorizationPresentationExchangeRequest.state,
            clientMetadata = authorizationPresentationExchangeRequest.clientMetadata,
            walletNonce = authorizationPresentationExchangeRequest.walletNonce
        )
        every { ResponseModeBasedHandlerFactory.get("unsupported_mode") } throws
                InvalidData("Unsupported response mode: unsupported_mode", "")

        authorizationResponseHandler.constructUnsignedVPToken(
            selectedCredentials = credentialsMap,
            authorizationRequest = authorizationPresentationExchangeRequest,
            responseUri = responseUrl,
            nonce = walletNonce
        )

        val exception = assertFailsWith<InvalidData> {
            authorizationResponseHandler.constructAndSendAuthorizationResponseToVerifier(
                authorizationRequest = request,
                vpTokenSigningResults = listOf(
                    VPTokenSigningResult(
                        id = RANDOM_UUID,
                        signedData = MOCK_SIGNED_DATA_1.toByteArray()
                    )
                ),
                dispatchInfo = dispatchInfoFor(request = request, responseUrl = responseUrl)
            )
        }
        assertEquals("Unsupported response mode: unsupported_mode", exception.message)
    }

    @Test
    fun `should throw exception when unsupported response type is provided`() {
        // Create a mock AuthorizationRequest with an unsupported response type
        val mockRequestWithUnsupportedType = mockk<AuthorizationRequest>()
        every { mockRequestWithUnsupportedType.responseType } returns "invalid_vp_token"

        // Populate internal state with valid request first
        authorizationResponseHandler.constructUnsignedVPToken(
            selectedCredentials = credentialsMap,
            authorizationRequest = authorizationPresentationExchangeRequest,
            responseUri = responseUrl,
            nonce = walletNonce
        )

        val exception = assertFailsWith<AuthorizationResponseConstructionFailure> {
            authorizationResponseHandler.constructAndSendAuthorizationResponseToVerifier(
                authorizationRequest = mockRequestWithUnsupportedType,
                vpTokenSigningResults = listOf(
                    VPTokenSigningResult(
                        id = RANDOM_UUID,
                        signedData = MOCK_SIGNED_DATA.toByteArray()
                    )
                ),
                dispatchInfo = dispatchInfoFor(responseUrl = responseUrl)
            )
        }
        assertEquals("server_error", exception.errorCode)
        assertEquals(
            AUTHORIZATION_RESPONSE_INTERNAL_ERROR_MESSAGE,
            exception.message
        )
        val cause = assertIs<InvalidData>(exception.cause)
        assertEquals(
            "Provided response_type - invalid_vp_token is not supported",
            cause.message
        )
    }

    @Test
    fun `should throw exception when format in signing results not found in unsigned tokens`() {
        val ldpOnly = mapOf("input1" to listOf(Credential(LDP_VC, ldpCredential1, "ldp-1")))
        authorizationResponseHandler.constructUnsignedVPToken(
            selectedCredentials = ldpOnly,
            authorizationRequest = authorizationPresentationExchangeRequest,
            responseUri = responseUrl,
            nonce = walletNonce
        )

        val exception = assertFailsWith<AuthorizationResponseConstructionFailure> {
            authorizationResponseHandler.constructAndSendAuthorizationResponseToVerifier(
                authorizationRequest = authorizationPresentationExchangeRequest,
                vpTokenSigningResults = listOf(
                    VPTokenSigningResult(
                        id = "uuid1",
                        signedData = MOCK_SIGNED_DATA.toByteArray()
                    ),
                    VPTokenSigningResult(
                        id = RANDOM_UUID,
                        signedData = "extra-signed-data".toByteArray()
                    )
                ),
                dispatchInfo = dispatchInfoFor(request = authorizationPresentationExchangeRequest, responseUrl = responseUrl)
            )
        }
        assertEquals("server_error", exception.errorCode)
        assertEquals(
            AUTHORIZATION_RESPONSE_INTERNAL_ERROR_MESSAGE,
            exception.message
        )
        val cause = assertIs<InvalidData>(exception.cause)
        assertEquals(
            "Unexpected VP token signing result for credential identifier(s): uuid1",
            cause.message
        )
    }

    @Test
    fun `should throw exception when network error occurs during response sending`() {
        every {
            mockResponseHandler.sendAuthorizationResponse(any(), any(), any())
        } throws IOException("Network connection failed")

        authorizationResponseHandler.constructUnsignedVPToken(
            selectedCredentials = credentialsMap,
            authorizationRequest = authorizationPresentationExchangeRequest,
            responseUri = responseUrl,
            nonce = walletNonce
        )

        val exception = assertFailsWith<IOException> {
            authorizationResponseHandler.constructAndSendAuthorizationResponseToVerifier(
                authorizationRequest = authorizationPresentationExchangeRequest,
                vpTokenSigningResults = listOf(
                    VPTokenSigningResult(
                        id = RANDOM_UUID,
                        signedData = MOCK_SIGNED_DATA_1.toByteArray()
                    )
                ),
                dispatchInfo = dispatchInfoFor(request = authorizationPresentationExchangeRequest, responseUrl = responseUrl)
            )
        }
        assertEquals("Network connection failed", exception.message)
    }

    @Test
    fun `should ignore empty credential lists for input descriptors`() {
        val input = mapOf(
            "input1" to listOf(Credential(LDP_VC, ldpCredential1, "ldp-1")),
            "input2" to emptyList()
        )

        val result = authorizationResponseHandler.constructUnsignedVPToken(
            selectedCredentials = input,
            authorizationRequest = authorizationPresentationExchangeRequest,
            responseUri = responseUrl,
            nonce = walletNonce
        )

        assertNotNull(result)
        assertTrue(result.isNotEmpty())
    }


    @Test
    fun ` wallet nonce is different for every construct unsignedVPToken call`() {
        val verifiableCredentials = mapOf(
            "input_descriptor1" to listOf(
                Credential(LDP_VC, ldpCredential1, "ldp-1")
            )
        )
        // First call
        authorizationResponseHandler.constructUnsignedVPToken(
            selectedCredentials = verifiableCredentials,
            authorizationRequest = authorizationPresentationExchangeRequest,
            responseUri = responseUrl,
            nonce = walletNonce
        )

        // Get the nonce from the first call using reflection
        val walletNonceField =
            AuthorizationResponseHandler::class.java.getDeclaredField("walletNonce")
        walletNonceField.isAccessible = true
        val firstNonce = walletNonceField.get(authorizationResponseHandler) as String

        // Second call
        authorizationResponseHandler.constructUnsignedVPToken(
            selectedCredentials = verifiableCredentials,
            authorizationRequest = authorizationPresentationExchangeRequest,
            responseUri = responseUrl,
            nonce = walletNonce
        )

        val secondNonce = walletNonceField.get(authorizationResponseHandler) as String

        assertNotEquals(
            "Wallet nonce should be different for every constructUnsignedVPTokenV1 call",
            firstNonce,
            secondNonce
        )
    }

    @Test
    fun `should successfully construct unsigned VP token for SD-JWT`() {
        val sdJwtVcList = listOf(sdJwtCredential1, sdJwtCredential2)
        val sdJwtCredentialMap = mapOf(
            "sdjwt-input" to listOf(
                Credential(VC_SD_JWT, sdJwtCredential1, "sdjwt-1"),
                Credential(VC_SD_JWT, sdJwtCredential2, "sdjwt-2")
            )
        )

        val localSdJwtMap = mapOf(
            UUID_1 to unsignedKBJwt,
            UUID_2 to "mock-unsigned-kb-jwt"
        )
        val localSdJwtTokens = localSdJwtMap.map { (uuid, kbt) ->
            UnsignedVPToken(RANDOM_UUID, VC_SD_JWT, "kid-$uuid", "ES256K", kbt.toByteArray())
        }
        mockkConstructor(UnsignedSdJwtVPTokenBuilder::class)
        every { anyConstructed<UnsignedSdJwtVPTokenBuilder>().build(any<List<CredentialInputDescriptorMapping>>()) } answers {
            val mappings = firstArg<List<CredentialInputDescriptorMapping>>()
            val uuids = localSdJwtMap.keys.toList()
            mappings.forEachIndexed { index, mapping ->
                if (index < uuids.size) mapping.identifier = uuids[index]
            }
            Pair(localSdJwtMap, localSdJwtTokens)
        }

        val result = authorizationResponseHandler.constructUnsignedVPToken(
            selectedCredentials = sdJwtCredentialMap,
            authorizationRequest = authorizationPresentationExchangeRequest,
            responseUri = responseUrl,
            nonce = walletNonce
        )

        assertNotNull(result)
        assertTrue(result.isNotEmpty())
        assertTrue(result.any { it.format == VC_SD_JWT })
    }

    @Test
    fun `should share SD-JWT VP successfully`() {
        val mockSdJwtUuidMap = mapOf(UUID_1 to "mock-kb-jwt")
        val mockUnsignedVPTokens = listOf(
            UnsignedVPToken(
                UUID_1,
                VC_SD_JWT,
                "kid-uuid-1",
                "ES256K",
                "mock-kb-jwt".toByteArray()
            )
        )

        setField(
            authorizationResponseHandler,
            "unsignedVPTokenResults",
            mapOf(VC_SD_JWT to Pair(mockSdJwtUuidMap, mockUnsignedVPTokens))
        )
        setField(
            authorizationResponseHandler, "formatToCredentialInputDescriptorMapping", mapOf(
                VC_SD_JWT to listOf(
                    CredentialInputDescriptorMapping(
                        VC_SD_JWT,
                        sdJwtCredential1,
                        "sdjwt-input"
                    ).apply { identifier = UUID_1 }
                )
            ))

        mockkObject(ResponseModeBasedHandlerFactory)
        every { ResponseModeBasedHandlerFactory.get("direct_post") } returns mockResponseHandler

        val request = AuthorizationPresentationExchangeRequest(
            clientId = authorizationPresentationExchangeRequest.clientId,
            responseType = "vp_token",
            responseMode = authorizationPresentationExchangeRequest.responseMode,
            presentationDefinition = authorizationPresentationExchangeRequest.presentationDefinition,
            responseUri = authorizationPresentationExchangeRequest.responseUri,
            redirectUri = authorizationPresentationExchangeRequest.redirectUri,
            nonce = authorizationPresentationExchangeRequest.nonce,
            state = authorizationPresentationExchangeRequest.state,
            clientMetadata = authorizationPresentationExchangeRequest.clientMetadata,
            walletNonce = authorizationPresentationExchangeRequest.walletNonce
        )

        val result = authorizationResponseHandler.constructAndSendAuthorizationResponseToVerifier(
            authorizationRequest = request,
            vpTokenSigningResults = listOf(
                VPTokenSigningResult(
                    id = UUID_1,
                    signedData = "mock-sd-jwt-signed".toByteArray()
                )
            ),
            dispatchInfo = dispatchInfoFor(request = request, responseUrl = responseUrl)
        )

        assertEquals(SUCCESS_RESPONSE_BODY, result.additionalParams)


        verify(exactly = 1) {
            mockResponseHandler.sendAuthorizationResponse(
                dispatchInfo = any(),
                authorizationResponse = any(),
                authorizationRequest = any()
            )
        }

    }

    @Test
    fun `should throw if SD-JWT format not found in unsigned tokens during constructAndSendAuthorizationResponseToVerifier`() {
        setField(
            authorizationResponseHandler,
            "unsignedVPTokenResults",
            emptyMap<FormatType, Pair<Any?, List<UnsignedVPToken>>>()
        )

        val request = AuthorizationPresentationExchangeRequest(
            clientId = authorizationPresentationExchangeRequest.clientId,
            responseType = "vp_token",
            responseMode = authorizationPresentationExchangeRequest.responseMode,
            presentationDefinition = authorizationPresentationExchangeRequest.presentationDefinition,
            responseUri = authorizationPresentationExchangeRequest.responseUri,
            redirectUri = authorizationPresentationExchangeRequest.redirectUri,
            nonce = authorizationPresentationExchangeRequest.nonce,
            state = authorizationPresentationExchangeRequest.state,
            clientMetadata = authorizationPresentationExchangeRequest.clientMetadata,
            walletNonce = authorizationPresentationExchangeRequest.walletNonce
        )

        val exception = assertFailsWith<AuthorizationResponseConstructionFailure> {
            authorizationResponseHandler.constructAndSendAuthorizationResponseToVerifier(
                request,
                listOf(
                    VPTokenSigningResult(
                        id = RANDOM_UUID,
                        signedData = MOCK_SIGNED_DATA.toByteArray()
                    )
                ),
                dispatchInfoFor(request = request, responseUrl = responseUrl)
            )
        }
        assertEquals("server_error", exception.errorCode)
        assertEquals(
            AUTHORIZATION_RESPONSE_INTERNAL_ERROR_MESSAGE,
            exception.message
        )
        assertIs<InvalidData>(exception.cause)
    }

    @Test
    fun `should share 2 SD-JWT credentials successfully`() {
        val sdJwtUuidMap = mapOf(UUID_1 to "kbjwt1", UUID_2 to "kbjwt2")
        val sdJwtTokens = sdJwtUuidMap.map { (uuid, kbt) ->
            UnsignedVPToken(uuid, VC_SD_JWT, "kid-$uuid", "ES256K", kbt.toByteArray())
        }

        setField(
            authorizationResponseHandler, "formatToCredentialInputDescriptorMapping", mapOf(
                VC_SD_JWT to listOf(
                    CredentialInputDescriptorMapping(
                        VC_SD_JWT,
                        sdJwtCredential1,
                        "142"
                    ).apply { identifier = UUID_1 },
                    CredentialInputDescriptorMapping(
                        VC_SD_JWT,
                        sdJwtCredential2,
                        "143"
                    ).apply { identifier = UUID_2 }
                )
            ))
        setField(
            authorizationResponseHandler, "unsignedVPTokenResults", mapOf(
                VC_SD_JWT to Pair(sdJwtUuidMap, sdJwtTokens)
            )
        )

        mockkObject(ResponseModeBasedHandlerFactory)
        every { ResponseModeBasedHandlerFactory.get(any()) } returns mockResponseHandler

        val request = AuthorizationPresentationExchangeRequest(
            clientId = authorizationPresentationExchangeRequest.clientId,
            responseType = "vp_token",
            responseMode = authorizationPresentationExchangeRequest.responseMode,
            presentationDefinition = authorizationPresentationExchangeRequest.presentationDefinition,
            responseUri = authorizationPresentationExchangeRequest.responseUri,
            redirectUri = authorizationPresentationExchangeRequest.redirectUri,
            nonce = authorizationPresentationExchangeRequest.nonce,
            state = authorizationPresentationExchangeRequest.state,
            clientMetadata = authorizationPresentationExchangeRequest.clientMetadata,
            walletNonce = authorizationPresentationExchangeRequest.walletNonce
        )

        val result = authorizationResponseHandler.constructAndSendAuthorizationResponseToVerifier(
            request,
            listOf(
                VPTokenSigningResult(
                    id = UUID_1,
                    signedData = MOCK_SIGNED_DATA_1.toByteArray()
                ),
                VPTokenSigningResult(
                    id = UUID_2,
                    signedData = MOCK_SIGNED_DATA_1.toByteArray()
                )
            ),
            dispatchInfoFor(request = request, responseUrl = responseUrl)
        )

        assertEquals(SUCCESS_RESPONSE_BODY, result.additionalParams)
    }

    @Test
    fun `should share 1 VC with vpToken as element and presentation submission correctly for vp_token response type`() {
        every {
            anyConstructed<MdocVPTokenBuilder>().build(
                any(),
                any(),
                any(),
                any()
            )
        } returns Triple(
            listOf(mdocVPToken), listOf(
                DescriptorMap("input2", "mdoc_vp", "$[0]", null),
            ), 1
        )
        authorizationResponseHandler.constructUnsignedVPToken(
            selectedCredentials = credentialMap2,
            authorizationRequest = authorizationPresentationExchangeRequest,
            responseUri = responseUrl,
            nonce = walletNonce
        )
        setField(
            authorizationResponseHandler, "formatToCredentialInputDescriptorMapping", mapOf(
                MSO_MDOC to listOf(
                    CredentialInputDescriptorMapping(
                        MSO_MDOC,
                        mdocCredential,
                        "input2"
                    ).apply { identifier = "org.iso.18013.5.1.mDL" }
                )
            )
        )
        setField(
            authorizationResponseHandler, "unsignedVPTokenResults", mapOf(
                MSO_MDOC to Pair(null, unsignedMdocVPToken),
            )
        )

        authorizationResponseHandler.constructAndSendAuthorizationResponseToVerifier(
            authorizationRequest = authorizationPresentationExchangeRequest,
            vpTokenSigningResults = listOf(
                VPTokenSigningResult(
                    id = RANDOM_UUID,
                    signedData = "mock-mdoc-signed".toByteArray()
                ),
            ),
            dispatchInfo = dispatchInfoFor(request = authorizationPresentationExchangeRequest, responseUrl = responseUrl)
        )

        // assert if mockResponseHandler is called with correct authorization response
        verify(exactly = 1) {
            mockResponseHandler.sendAuthorizationResponse(
                dispatchInfo = any(),
                authorizationResponse = match {
                    val pe = it as AuthorizationResponse.PresentationExchange
                    // Note: If only one vp token is being shared then tha path in the presentation submission takes value as $ and VP token is an element only and not array
                    assertEquals(
                        "VPTokenElement(value=MdocVPToken(base64EncodedDeviceResponse=base64EncodedDeviceResponse))",
                        pe.vpToken.toString()
                    )
                    assertEquals(
                        "PresentationSubmission(id=649d581c-f291-4969-9cd5-2c27385a348f, definitionId=649d581c-f891-4969-9cd5-2c27385a348f, descriptorMap=[DescriptorMap(id=input2, format=mdoc_vp, path=$, pathNested=null)])",
                        pe.presentationSubmission.toString()
                    )
                    pe.presentationSubmission.descriptorMap.size == 1
                },
                authorizationRequest = any()
            )
        }
    }

// sharing of multiple credentials of different formats

    @Test
    fun `should share credentials for 2LDP, 2SD-JWT and 2MSO-MDOC VC`() {
        val ldpUnsignedTokens = listOf(
            unsignedLdpVPToken.first().copy(id = LDP_CREDENTIAL_UUID),
            unsignedLdpVPToken.first().copy(id = LDP_CREDENTIAL_UUID_2)
        )
        every { anyConstructed<UnsignedLdpVPTokenBuilder>().build(any<List<CredentialInputDescriptorMapping>>()) } returns Pair(
            mapOf(
                LDP_CREDENTIAL_UUID to vpTokenSigningPayload2.copy(
                    verifiableCredential = listOf(
                        ldpCredential1
                    )
                ),
                LDP_CREDENTIAL_UUID_2 to vpTokenSigningPayload2.copy(
                    verifiableCredential = listOf(
                        ldpCredential2
                    )
                )
            ),
            ldpUnsignedTokens
        )
        every {
            anyConstructed<LdpVPTokenBuilder>().build(
                any(),
                any(),
                any(),
                any()
            )
        } returns Triple(
            listOf(
                ldpVPToken2.copy(verifiableCredential = listOf(ldpCredential1)),
                ldpVPToken2.copy(verifiableCredential = listOf(ldpCredential2))
            ), listOf(
                DescriptorMap(
                    "input1",
                    "ldp_vp",
                    "$[2]",
                    PathNested("input1", "ldp_vc", VERIFIABLE_CREDENTIAL_PATH)
                ),
                DescriptorMap(
                    "input1",
                    "ldp_vp",
                    "$[3]",
                    PathNested("input1", "ldp_vc", VERIFIABLE_CREDENTIAL_PATH)
                )
            ), 4
        )
        every {
            anyConstructed<MdocVPTokenBuilder>().build(
                any(),
                any(),
                any(),
                any()
            )
        } returns Triple(
            listOf(mdocVPToken), listOf(
                DescriptorMap("input2", "mdoc_vp", "$[4]", null),
            ), 5
        )


        setField(
            authorizationResponseHandler, "formatToCredentialInputDescriptorMapping", mapOf(
                LDP_VC to listOf(
                    CredentialInputDescriptorMapping(
                        LDP_VC,
                        ldpCredential1,
                        "input1"
                    ).apply { identifier = LDP_CREDENTIAL_UUID },
                    CredentialInputDescriptorMapping(
                        LDP_VC,
                        ldpCredential2,
                        "input1"
                    ).apply { identifier = LDP_CREDENTIAL_UUID_2 }
                ),
                MSO_MDOC to listOf(
                    CredentialInputDescriptorMapping(
                        MSO_MDOC,
                        mdocCredential,
                        "input2"
                    ).apply { identifier = MDOC_CREDENTIAL_UUID_1 }
                ),
                VC_SD_JWT to listOf(
                    CredentialInputDescriptorMapping(
                        VC_SD_JWT,
                        sdJwtCredential1,
                        "input3"
                    ).apply { identifier = SD_JWT_CREDENTIAL_UUID_1 },
                    CredentialInputDescriptorMapping(
                        VC_SD_JWT,
                        sdJwtCredential2,
                        "input3"
                    ).apply { identifier = SD_JWT_CREDENTIAL_UUID_2 }
                )
            )
        )

        // Align reconstructed signing expectations with the explicit signing-result IDs in this test.
        setField(
            authorizationResponseHandler,
            "unsignedVPTokenResults",
            mapOf(
                LDP_VC to Pair(
                    mapOf(
                        LDP_CREDENTIAL_UUID to vpTokenSigningPayload2.copy(verifiableCredential = listOf(ldpCredential1)),
                        LDP_CREDENTIAL_UUID_2 to vpTokenSigningPayload2.copy(verifiableCredential = listOf(ldpCredential2))
                    ),
                    ldpUnsignedTokens
                ),
                MSO_MDOC to Pair(
                    mapOf(MDOC_CREDENTIAL_UUID_1 to mdocDocTypeToDeviceAuthBytes.values.first()),
                    listOf(unsignedMdocVPToken.first().copy(id = MDOC_CREDENTIAL_UUID_1))
                ),
                VC_SD_JWT to Pair(
                    mapOf(
                        SD_JWT_CREDENTIAL_UUID_1 to "unsignedKBT1",
                        SD_JWT_CREDENTIAL_UUID_2 to "unsignedKBT2"
                    ),
                    listOf(
                        UnsignedVPToken(SD_JWT_CREDENTIAL_UUID_1, VC_SD_JWT, "kid-sd-jwt-uuid1", "ES256K", "unsignedKBT1".toByteArray()),
                        UnsignedVPToken(SD_JWT_CREDENTIAL_UUID_2, VC_SD_JWT, "kid-sd-jwt-uuid2", "ES256K", "unsignedKBT2".toByteArray())
                    )
                )
            )
        )

        val result = authorizationResponseHandler.constructAndSendAuthorizationResponseToVerifier(
            authorizationRequest = authorizationPresentationExchangeRequest,
            vpTokenSigningResults = listOf(
                VPTokenSigningResult(
                    id = LDP_CREDENTIAL_UUID,
                    signedData = "mock-ldp-signed-1".toByteArray()
                ),
                VPTokenSigningResult(
                    id = LDP_CREDENTIAL_UUID_2,
                    signedData = "mock-ldp-signed-2".toByteArray()
                ),
                VPTokenSigningResult(
                    id = MDOC_CREDENTIAL_UUID_1,
                    signedData = "mock-mdoc-signed".toByteArray()
                ),
                VPTokenSigningResult(
                    id = SD_JWT_CREDENTIAL_UUID_1,
                    signedData = "mock-sdjwt-signed".toByteArray()
                ),
                VPTokenSigningResult(
                    id = SD_JWT_CREDENTIAL_UUID_2,
                    signedData = "mock-sdjwt-signed".toByteArray()
                )
            ),
            dispatchInfo = dispatchInfoFor(request = authorizationPresentationExchangeRequest, responseUrl = responseUrl)
        )

        assertEquals(SUCCESS_RESPONSE_BODY, result.additionalParams)
        // assert if mockResponseHandler is called with correct authorization response
        verify(exactly = 1) {
            mockResponseHandler.sendAuthorizationResponse(
                dispatchInfo = any(),
                authorizationResponse = match {
                    val pe = it as AuthorizationResponse.PresentationExchange
                    // Note: If only more than vp token is being shared then the path in presentation submission takes value as $[<index>] and VP token is an array holding all tokens together
                    assertEquals(
                        """
                    PresentationSubmission(id=649d581c-f291-4969-9cd5-2c27385a348f, definitionId=649d581c-f891-4969-9cd5-2c27385a348f, descriptorMap=[DescriptorMap(id=input1, format=ldp_vp, path=$[2], pathNested=PathNested(id=input1, format=ldp_vc, path=$.verifiableCredential[0])), DescriptorMap(id=input1, format=ldp_vp, path=$[3], pathNested=PathNested(id=input1, format=ldp_vc, path=$.verifiableCredential[0])), DescriptorMap(id=input2, format=mdoc_vp, path=$[4], pathNested=null), DescriptorMap(id=input3, format=vc+sd-jwt, path=$[5], pathNested=null), DescriptorMap(id=input3, format=vc+sd-jwt, path=$[6], pathNested=null)])
                        """.trimIndent(), pe.presentationSubmission.toString()
                    )
                    true
                },
                authorizationRequest = any()
            )
        }
    }


    // Tests for sendAuthorizationError

// Tests for sendAuthorizationError

    @Test
    fun `sendAuthorizationError should send OpenID4VPExceptions payload including state`() {
        val bodySlot = slot<Map<String, String>>()
        val headersSlot = slot<Map<String, String>>()
        every {
            NetworkManagerClient.sendHTTPRequest(
                url = any(),
                method = any(),
                bodyParams = capture(bodySlot),
                headers = capture(headersSlot)
            )
        } returns NetworkResponse(400, "mock-error-response", mapOf())

        val ex = InvalidData("Some invalid data", "TestClass")
        val result = authorizationResponseHandler.sendAuthorizationError(
            dispatchInfo = dispatchInfoFor(request = authorizationPresentationExchangeRequest, responseUrl = VERIFIER_CALLBACK_URI),
            authorizationRequest = authorizationPresentationExchangeRequest,
            exception = ex
        )

        assertEquals("mock-error-response", result.additionalParams)
        assertTrue(bodySlot.isCaptured)
        assertEquals(authorizationPresentationExchangeRequest.state, bodySlot.captured["state"])
        assertTrue(headersSlot.captured["Content-Type"]!!.contains("application/x-www-form-urlencoded"))
    }

    @Test
    fun `sendAuthorizationError should wrap generic exception`() {
        val bodySlot = slot<Map<String, String>>()
        every {
            NetworkManagerClient.sendHTTPRequest(
                url = any(),
                method = any(),
                bodyParams = capture(bodySlot),
                headers = any()
            )
        } returns NetworkResponse(500, "\"message\":\"generic-error-response\"", mapOf())

        val ex = RuntimeException("Boom")
        val result = authorizationResponseHandler.sendAuthorizationError(
            dispatchInfo = dispatchInfoFor(request = authorizationPresentationExchangeRequest, responseUrl = VERIFIER_CALLBACK_URI),
            authorizationRequest = authorizationPresentationExchangeRequest,
            exception = ex
        )

        assertEquals("\"message\":\"generic-error-response\"", result.additionalParams)
        assertTrue(bodySlot.captured.containsKey("error"))
        assertTrue(bodySlot.captured.values.any { it.contains("Boom") })
    }

    @Test
    fun `sendAuthorizationError should throw when responseUri is null`() {
        val ex = InvalidData("msg", "Test")
        assertFailsWith<ErrorDispatchFailure> {
            authorizationResponseHandler.sendAuthorizationError(
                dispatchInfo = null,
                authorizationRequest = authorizationPresentationExchangeRequest,
                exception = ex
            )
        }
    }

    @Test
    fun `sendAuthorizationError should throw ErrorDispatchFailure when network fails`() {
        every {
            NetworkManagerClient.sendHTTPRequest(any(), any(), any(), any())
        } throws RuntimeException("network down")

        val ex = InvalidData("msg", "Test")
        val failure = assertFailsWith<ErrorDispatchFailure> {
            authorizationResponseHandler.sendAuthorizationError(
                dispatchInfo = dispatchInfoFor(request = authorizationPresentationExchangeRequest, responseUrl = VERIFIER_CALLBACK_URI),
                authorizationRequest = authorizationPresentationExchangeRequest,
                exception = ex
            )
        }
        assertTrue(failure.message.contains("network down"))
    }


    @Test
    fun `constructAuthorizationErrorResponse should handle OpenID4VPExceptions`() {
        mockkObject(ResponseModeBasedHandlerFactory)
        every { ResponseModeBasedHandlerFactory.get("direct_post") } returns mockResponseHandler
        every {
            mockResponseHandler.getAuthorizationErrorResponse(
                dispatchInfo = any(),
                authorizationResponse = any<AuthorizationErrorResponse>(),
                authorizationRequest = any<AuthorizationRequest>()
            )
        } returns mapOf(
            "error" to "invalid_request",
            "error_description" to INVALID_DATA_PROVIDED_MESSAGE
        )

        val exception = InvalidData(INVALID_DATA_PROVIDED_MESSAGE, "TestClass")

        val result = authorizationResponseHandler.constructAuthorizationErrorResponse(
            dispatchInfo = dispatchInfoFor(request = authorizationPresentationExchangeRequest),
            exception = exception,
            walletNonce = WALLET_NONCE_VALUE,
            authorizationRequest = authorizationPresentationExchangeRequest
        )

        assertEquals(
            mapOf(
                "error" to "invalid_request",
                "error_description" to INVALID_DATA_PROVIDED_MESSAGE
            ), result
        )

        verify {
            mockResponseHandler.getAuthorizationErrorResponse(
                dispatchInfo = any(),
                authorizationResponse = any<AuthorizationErrorResponse>(),
                authorizationRequest = authorizationPresentationExchangeRequest
            )
        }
    }

    @Test
    fun `constructAuthorizationErrorResponse should handle AccessDenied exception`() {
        mockkObject(ResponseModeBasedHandlerFactory)
        every { ResponseModeBasedHandlerFactory.get("direct_post") } returns mockResponseHandler
        every {
            mockResponseHandler.getAuthorizationErrorResponse(
                dispatchInfo = any(),
                authorizationResponse = any<AuthorizationErrorResponse>(),
                authorizationRequest = any<AuthorizationRequest>()
            )
        } returns mapOf("error" to "access_denied")

        val exception = AccessDenied("Access denied to resource", "TestClass")

        val result = authorizationResponseHandler.constructAuthorizationErrorResponse(
            dispatchInfo = dispatchInfoFor(request = authorizationPresentationExchangeRequest),
            exception = exception,
            walletNonce = WALLET_NONCE_VALUE,
            authorizationRequest = authorizationPresentationExchangeRequest
        )

        assertEquals(mapOf("error" to "access_denied"), result)
    }

    @Test
    fun `constructAuthorizationErrorResponse should handle InvalidVerifier exception`() {
        mockkObject(ResponseModeBasedHandlerFactory)
        every { ResponseModeBasedHandlerFactory.get("direct_post") } returns mockResponseHandler
        every {
            mockResponseHandler.getAuthorizationErrorResponse(
                dispatchInfo = any(),
                authorizationResponse = any<AuthorizationErrorResponse>(),
                authorizationRequest = any<AuthorizationRequest>()
            )
        } returns mapOf("error" to "invalid_client")

        val exception = InvalidVerifier("Invalid verifier provided", "TestClass")

        val result = authorizationResponseHandler.constructAuthorizationErrorResponse(
            dispatchInfo = dispatchInfoFor(request = authorizationPresentationExchangeRequest),
            exception = exception,
            walletNonce = WALLET_NONCE_VALUE,
            authorizationRequest = authorizationPresentationExchangeRequest
        )

        assertEquals(mapOf("error" to "invalid_client"), result)
    }

    @Test
    fun `constructAuthorizationErrorResponse should handle generic exceptions as GenericFailure`() {
        mockkObject(ResponseModeBasedHandlerFactory)
        every { ResponseModeBasedHandlerFactory.get("direct_post") } returns mockResponseHandler
        every {
            mockResponseHandler.getAuthorizationErrorResponse(
                dispatchInfo = any(),
                authorizationResponse = any<AuthorizationErrorResponse>(),
                authorizationRequest = any<AuthorizationRequest>()
            )
        } returns mapOf("error" to "server_error")

        val genericException = RuntimeException("Unexpected runtime error")

        val result = authorizationResponseHandler.constructAuthorizationErrorResponse(
            dispatchInfo = dispatchInfoFor(request = authorizationPresentationExchangeRequest),
            exception = genericException,
            walletNonce = WALLET_NONCE_VALUE,
            authorizationRequest = authorizationPresentationExchangeRequest
        )

        assertEquals(mapOf("error" to "server_error"), result)
    }

    @Test
    fun `constructAuthorizationErrorResponse should handle exception with null message`() {
        mockkObject(ResponseModeBasedHandlerFactory)
        every { ResponseModeBasedHandlerFactory.get("direct_post") } returns mockResponseHandler
        every {
            mockResponseHandler.getAuthorizationErrorResponse(
                dispatchInfo = any(),
                authorizationResponse = any<AuthorizationErrorResponse>(),
                authorizationRequest = any<AuthorizationRequest>()
            )
        } returns mapOf("error" to "server_error")

        val exceptionWithNullMessage = RuntimeException(null as String?)

        val result = authorizationResponseHandler.constructAuthorizationErrorResponse(
            dispatchInfo = dispatchInfoFor(request = authorizationPresentationExchangeRequest),
            exception = exceptionWithNullMessage,
            walletNonce = WALLET_NONCE_VALUE,
            authorizationRequest = authorizationPresentationExchangeRequest
        )

        assertEquals(mapOf("error" to "server_error"), result)
    }

    @Test
    fun `constructAuthorizationErrorResponse should preserve state from authorization request`() {
        mockkObject(ResponseModeBasedHandlerFactory)
        every { ResponseModeBasedHandlerFactory.get("direct_post") } returns mockResponseHandler

        val capturedErrorResponse = slot<AuthorizationErrorResponse>()
        every {
            mockResponseHandler.getAuthorizationErrorResponse(
                dispatchInfo = any(),
                authorizationResponse = capture(capturedErrorResponse),
                authorizationRequest = authorizationPresentationExchangeRequest
            )
        } returns mapOf("state" to "preserved")

        val exception = InvalidData("Test error", "TestClass")

        authorizationResponseHandler.constructAuthorizationErrorResponse(
            dispatchInfo = dispatchInfoFor(request = authorizationPresentationExchangeRequest),
            exception = exception,
            walletNonce = WALLET_NONCE_VALUE,
            authorizationRequest = authorizationPresentationExchangeRequest
        )

        assertEquals(
            authorizationPresentationExchangeRequest.state,
            capturedErrorResponse.captured.state
        )
    }

    @Test
    fun `constructAuthorizationErrorResponse should work with different response modes`() {
        val jwtRequest = authorizationRequestForResponseModeJWT

        mockkObject(ResponseModeBasedHandlerFactory)
        every { ResponseModeBasedHandlerFactory.get("direct_post.jwt") } returns mockResponseHandler
        every {
            mockResponseHandler.getAuthorizationErrorResponse(
                dispatchInfo = any(),
                authorizationResponse = any<AuthorizationErrorResponse>(),
                authorizationRequest = any<AuthorizationRequest>()
            )
        } returns mapOf("jwt" to "encrypted_response")

        val exception = InvalidTransactionData("Invalid transaction", "TestClass")

        val result = authorizationResponseHandler.constructAuthorizationErrorResponse(
            dispatchInfo = dispatchInfoFor(request = jwtRequest),
            exception = exception,
            walletNonce = WALLET_NONCE_VALUE,
            authorizationRequest = jwtRequest
        )

        assertEquals(mapOf("jwt" to "encrypted_response"), result)
    }

    @Test
    fun `constructAuthorizationErrorResponse should handle MissingInput exception`() {
        mockkObject(ResponseModeBasedHandlerFactory)
        every { ResponseModeBasedHandlerFactory.get("direct_post") } returns mockResponseHandler
        every {
            mockResponseHandler.getAuthorizationErrorResponse(
                dispatchInfo = any(),
                authorizationResponse = any<AuthorizationErrorResponse>(),
                authorizationRequest = any<AuthorizationRequest>()
            )
        } returns mapOf("error" to "invalid_request")

        val exception = MissingInput(
            "presentation_definition",
            "Missing required field: presentation_definition",
            "TestClass"
        )

        val result = authorizationResponseHandler.constructAuthorizationErrorResponse(
            dispatchInfo = dispatchInfoFor(request = authorizationPresentationExchangeRequest),
            exception = exception,
            walletNonce = WALLET_NONCE_VALUE,
            authorizationRequest = authorizationPresentationExchangeRequest
        )

        assertEquals(mapOf("error" to "invalid_request"), result)
    }

    @Test
    fun `constructAuthorizationErrorResponse should handle InvalidInputPattern exception`() {
        mockkObject(ResponseModeBasedHandlerFactory)
        every { ResponseModeBasedHandlerFactory.get("direct_post") } returns mockResponseHandler
        every {
            mockResponseHandler.getAuthorizationErrorResponse(
                dispatchInfo = any(),
                authorizationResponse = any<AuthorizationErrorResponse>(),
                authorizationRequest = any<AuthorizationRequest>()
            )
        } returns mapOf("error" to "invalid_request")

        val exception = InvalidInputPattern(listOf("path", "to", "field"), "TestClass")

        val result = authorizationResponseHandler.constructAuthorizationErrorResponse(
            dispatchInfo = dispatchInfoFor(request = authorizationPresentationExchangeRequest),
            exception = exception,
            walletNonce = WALLET_NONCE_VALUE,
            authorizationRequest = authorizationPresentationExchangeRequest
        )

        assertEquals(mapOf("error" to "invalid_request"), result)
    }

    @Test
    fun `constructAuthorizationErrorResponse should handle JsonEncodingFailed exception`() {
        mockkObject(ResponseModeBasedHandlerFactory)
        every { ResponseModeBasedHandlerFactory.get("direct_post") } returns mockResponseHandler
        every {
            mockResponseHandler.getAuthorizationErrorResponse(
                dispatchInfo = any(),
                authorizationResponse = any<AuthorizationErrorResponse>(),
                authorizationRequest = any<AuthorizationRequest>()
            )
        } returns mapOf("error" to "invalid_request")

        val exception = JsonEncodingFailed("fieldPath", "JSON encoding error", "TestClass")

        val result = authorizationResponseHandler.constructAuthorizationErrorResponse(
            dispatchInfo = dispatchInfoFor(request = authorizationPresentationExchangeRequest),
            exception = exception,
            walletNonce = WALLET_NONCE_VALUE,
            authorizationRequest = authorizationPresentationExchangeRequest
        )

        assertEquals(mapOf("error" to "invalid_request"), result)
    }

    // Tests for constructVPResponse

    @Test
    fun `constructVPResponse should successfully construct response with valid inputs`() {
        // Setup mocks
        mockkObject(ResponseModeBasedHandlerFactory)
        every { ResponseModeBasedHandlerFactory.get("direct_post") } returns mockResponseHandler
        val state = assertNotNull(authorizationPresentationExchangeRequest.state)
        every {
            mockResponseHandler.getAuthorizationResponse(
                dispatchInfo = any(),
                authorizationResponse = any<AuthorizationResponse>(),
                authorizationRequest = any<AuthorizationRequest>()
            )
        } returns mapOf(
            "response" to "finalized",
            "state" to state
        )

        // Setup internal state first
        authorizationResponseHandler.constructUnsignedVPToken(
            selectedCredentials = selectedLdpVcCredentialsList,
            authorizationRequest = authorizationPresentationExchangeRequest,
            responseUri = MOCK_VERIFIER_URL,
            nonce = walletNonce
        )

        val result = authorizationResponseHandler.constructVPResponse(
            vpTokenSigningResults = listOf(
                VPTokenSigningResult(
                    id = RANDOM_UUID,
                    signedData = MOCK_SIGNED_DATA.toByteArray()
                )
            ),
            authorizationRequest = authorizationPresentationExchangeRequest,
            dispatchInfo = dispatchInfoFor(request = authorizationPresentationExchangeRequest)
        )

        assertEquals(
            mapOf(
                "response" to "finalized",
                "state" to authorizationPresentationExchangeRequest.state
            ),
            result
        )

        verify {
            mockResponseHandler.getAuthorizationResponse(
                dispatchInfo = any(),
                authorizationResponse = any<AuthorizationResponse>(),
                authorizationRequest = authorizationPresentationExchangeRequest
            )
        }
    }

    @Test
    fun `constructVPResponse should handle multiple format types`() {
        mockkObject(ResponseModeBasedHandlerFactory)
        every { ResponseModeBasedHandlerFactory.get("direct_post") } returns mockResponseHandler

        val capturedResponse = slot<AuthorizationResponse>()
        every {
            mockResponseHandler.getAuthorizationResponse(
                dispatchInfo = any(),
                authorizationResponse = capture(capturedResponse),
                authorizationRequest = authorizationPresentationExchangeRequest
            )
        } returns mapOf("multi_format" to "response")

        // Setup internal state with multiple formats
        authorizationResponseHandler.constructUnsignedVPToken(
            selectedCredentials = selectedLdpVcCredentialsList + selectedMdocCredentialsList,
            authorizationRequest = authorizationPresentationExchangeRequest,
            responseUri = MOCK_VERIFIER_URL,
            nonce = walletNonce
        )

        val result = authorizationResponseHandler.constructVPResponse(
            vpTokenSigningResults = listOf(
                VPTokenSigningResult(
                    id = RANDOM_UUID,
                    signedData = MOCK_SIGNED_DATA_1.toByteArray()
                )
            ),
            authorizationRequest = authorizationPresentationExchangeRequest,
            dispatchInfo = dispatchInfoFor(request = authorizationPresentationExchangeRequest)
        )

        assertEquals(mapOf("multi_format" to "response"), result)
        val pe = capturedResponse.captured as AuthorizationResponse.PresentationExchange
        assertNotNull(pe.presentationSubmission)
        assertNotNull(pe.vpToken)
        assertEquals(
            authorizationPresentationExchangeRequest.state,
            capturedResponse.captured.state
        )
    }

    @Test
    fun `constructVPResponse should handle different response modes`() {
        val jwtRequest = authorizationRequestForResponseModeJWT

        mockkObject(ResponseModeBasedHandlerFactory)
        every { ResponseModeBasedHandlerFactory.get("direct_post.jwt") } returns mockResponseHandler
        every {
            mockResponseHandler.getAuthorizationResponse(
                dispatchInfo = any(),
                authorizationResponse = any<AuthorizationResponse>(),
                authorizationRequest = any<AuthorizationRequest>()
            )
        } returns mapOf("encrypted" to "jwt_response")

        // Setup internal state
        authorizationResponseHandler.constructUnsignedVPToken(
            selectedCredentials = selectedLdpVcCredentialsList,
            authorizationRequest = jwtRequest,
            responseUri = MOCK_VERIFIER_URL,
            nonce = walletNonce
        )

        val result = authorizationResponseHandler.constructVPResponse(
            vpTokenSigningResults = listOf(
                VPTokenSigningResult(
                    id = RANDOM_UUID,
                    signedData = MOCK_SIGNED_DATA.toByteArray()
                )
            ),
            authorizationRequest = jwtRequest,
            dispatchInfo = dispatchInfoFor(request = jwtRequest)
        )

        assertEquals(mapOf("encrypted" to "jwt_response"), result)
    }

    @Test
    fun `constructVPResponse should throw error for unsupported response type`() {
        val invalidRequest = AuthorizationPresentationExchangeRequest(
            clientId = authorizationPresentationExchangeRequest.clientId,
            responseType = "invalid_response_type",
            responseMode = authorizationPresentationExchangeRequest.responseMode,
            presentationDefinition = authorizationPresentationExchangeRequest.presentationDefinition,
            responseUri = authorizationPresentationExchangeRequest.responseUri,
            redirectUri = authorizationPresentationExchangeRequest.redirectUri,
            nonce = authorizationPresentationExchangeRequest.nonce,
            state = authorizationPresentationExchangeRequest.state,
            clientMetadata = authorizationPresentationExchangeRequest.clientMetadata,
            walletNonce = authorizationPresentationExchangeRequest.walletNonce
        )

        // Setup internal state
        authorizationResponseHandler.constructUnsignedVPToken(
            selectedCredentials = selectedLdpVcCredentialsList,
            authorizationRequest = authorizationPresentationExchangeRequest, // Use original for setup
            responseUri = MOCK_VERIFIER_URL,
            nonce = walletNonce
        )

        val exception = assertFailsWith<AuthorizationResponseConstructionFailure> {
            authorizationResponseHandler.constructVPResponse(
                vpTokenSigningResults = listOf(
                    VPTokenSigningResult(
                        id = RANDOM_UUID,
                        signedData = MOCK_SIGNED_DATA.toByteArray()
                    )
                ),
                authorizationRequest = invalidRequest,
                dispatchInfo = dispatchInfoFor(request = invalidRequest)
            )
        }
        assertEquals("server_error", exception.errorCode)
        assertEquals(
            AUTHORIZATION_RESPONSE_INTERNAL_ERROR_MESSAGE,
            exception.message
        )
        val cause = assertIs<InvalidData>(exception.cause)
        assertTrue(cause.message!!.contains("invalid_response_type"))
        assertTrue(cause.message!!.contains("not supported"))
    }

    @Test
    fun `constructVPResponse should throw error when vpTokenSigningResults is missing formats`() {
        // Setup internal state with multiple formats
        authorizationResponseHandler.constructUnsignedVPToken(
            selectedCredentials = selectedLdpVcCredentialsList + selectedMdocCredentialsList,
            authorizationRequest = authorizationPresentationExchangeRequest,
            responseUri = MOCK_VERIFIER_URL,
            nonce = walletNonce
        )

        // Use distinct token identifiers per format so a partial result can be detected reliably.
        setField(
            authorizationResponseHandler,
            "unsignedVPTokenResults",
            mapOf(
                LDP_VC to Pair(
                    vpTokenSigningPayload,
                    unsignedLdpVPToken.map { it.copy(id = "ldp-uuid") }
                ),
                MSO_MDOC to Pair(
                    mdocDocTypeToDeviceAuthBytes,
                    unsignedMdocVPToken.map { it.copy(id = "mdoc-uuid") }
                )
            )
        )

        // Provide only partial signing results (missing MSO_MDOC)
        val exception = assertFailsWith<AuthorizationResponseConstructionFailure> {
            authorizationResponseHandler.constructVPResponse(
                vpTokenSigningResults = listOf(
                    VPTokenSigningResult(
                        id = "ldp-uuid",
                        signedData = MOCK_SIGNED_DATA.toByteArray()
                    )
                ),
                authorizationRequest = authorizationPresentationExchangeRequest,
                dispatchInfo = dispatchInfoFor(request = authorizationPresentationExchangeRequest)
            )
        }
        assertEquals("server_error", exception.errorCode)
        assertEquals(
            AUTHORIZATION_RESPONSE_INTERNAL_ERROR_MESSAGE,
            exception.message
        )
        val cause = assertIs<MissingInput>(exception.cause)
        assertTrue(cause.message!!.contains("mdoc-uuid"))
    }

    @Test
    fun `constructVPResponse should preserve state from authorization request`() {
        val requestWithState = AuthorizationPresentationExchangeRequest(
            clientId = authorizationPresentationExchangeRequest.clientId,
            responseType = authorizationPresentationExchangeRequest.responseType,
            responseMode = authorizationPresentationExchangeRequest.responseMode,
            presentationDefinition = authorizationPresentationExchangeRequest.presentationDefinition,
            responseUri = authorizationPresentationExchangeRequest.responseUri,
            redirectUri = authorizationPresentationExchangeRequest.redirectUri,
            nonce = authorizationPresentationExchangeRequest.nonce,
            state = TEST_STATE_VALUE,
            clientMetadata = authorizationPresentationExchangeRequest.clientMetadata,
            walletNonce = authorizationPresentationExchangeRequest.walletNonce
        )

        mockkObject(ResponseModeBasedHandlerFactory)
        every { ResponseModeBasedHandlerFactory.get("direct_post") } returns mockResponseHandler

        val capturedResponse = slot<AuthorizationResponse>()
        every {
            mockResponseHandler.getAuthorizationResponse(
                dispatchInfo = any(),
                authorizationResponse = capture(capturedResponse),
                authorizationRequest = requestWithState
            )
        } returns mapOf("state" to TEST_STATE_VALUE)

        // Setup internal state
        authorizationResponseHandler.constructUnsignedVPToken(
            selectedCredentials = selectedLdpVcCredentialsList,
            authorizationRequest = requestWithState,
            responseUri = MOCK_VERIFIER_URL,
            nonce = walletNonce
        )

        authorizationResponseHandler.constructVPResponse(
            vpTokenSigningResults = listOf(
                VPTokenSigningResult(
                    id = RANDOM_UUID,
                    signedData = MOCK_SIGNED_DATA.toByteArray()
                )
            ),
            authorizationRequest = requestWithState,
            dispatchInfo = dispatchInfoFor(request = requestWithState)
        )

        assertEquals(TEST_STATE_VALUE, capturedResponse.captured.state)
    }

    @Test
    fun `constructVPResponse should handle null state in authorization request`() {
        val requestWithNullState = AuthorizationPresentationExchangeRequest(
            clientId = authorizationPresentationExchangeRequest.clientId,
            responseType = authorizationPresentationExchangeRequest.responseType,
            responseMode = authorizationPresentationExchangeRequest.responseMode,
            presentationDefinition = authorizationPresentationExchangeRequest.presentationDefinition,
            responseUri = authorizationPresentationExchangeRequest.responseUri,
            redirectUri = authorizationPresentationExchangeRequest.redirectUri,
            nonce = authorizationPresentationExchangeRequest.nonce,
            state = null,
            clientMetadata = authorizationPresentationExchangeRequest.clientMetadata,
            walletNonce = authorizationPresentationExchangeRequest.walletNonce
        )

        mockkObject(ResponseModeBasedHandlerFactory)
        every { ResponseModeBasedHandlerFactory.get("direct_post") } returns mockResponseHandler

        val capturedResponse = slot<AuthorizationResponse>()
        every {
            mockResponseHandler.getAuthorizationResponse(
                dispatchInfo = any(),
                authorizationResponse = capture(capturedResponse),
                authorizationRequest = requestWithNullState
            )
        } returns mapOf("response" to "no_state")

        // Setup internal state
        authorizationResponseHandler.constructUnsignedVPToken(
            selectedCredentials = selectedLdpVcCredentialsList,
            authorizationRequest = requestWithNullState,
            responseUri = MOCK_VERIFIER_URL,
            nonce = walletNonce
        )

        authorizationResponseHandler.constructVPResponse(
            vpTokenSigningResults = listOf(
                VPTokenSigningResult(
                    id = RANDOM_UUID,
                    signedData = MOCK_SIGNED_DATA.toByteArray()
                )
            ),
            authorizationRequest = requestWithNullState,
            dispatchInfo = dispatchInfoFor(request = requestWithNullState)
        )

        assertNull(capturedResponse.captured.state)
    }

    @Test
    fun `constructVPResponse should create single VP token element when one format`() {
        mockkObject(ResponseModeBasedHandlerFactory)
        every { ResponseModeBasedHandlerFactory.get("direct_post") } returns mockResponseHandler

        val capturedResponse = slot<AuthorizationResponse>()
        every {
            mockResponseHandler.getAuthorizationResponse(
                dispatchInfo = any(),
                authorizationResponse = capture(capturedResponse),
                authorizationRequest = authorizationPresentationExchangeRequest
            )
        } returns mapOf("single" to "vp_token")

        // Setup internal state with single format
        authorizationResponseHandler.constructUnsignedVPToken(
            selectedCredentials = selectedLdpVcCredentialsList,
            authorizationRequest = authorizationPresentationExchangeRequest,
            responseUri = MOCK_VERIFIER_URL,
            nonce = walletNonce
        )

        authorizationResponseHandler.constructVPResponse(
            vpTokenSigningResults = listOf(
                VPTokenSigningResult(
                    id = RANDOM_UUID,
                    signedData = MOCK_SIGNED_DATA.toByteArray()
                )
            ),
            authorizationRequest = authorizationPresentationExchangeRequest,
            dispatchInfo = dispatchInfoFor(request = authorizationPresentationExchangeRequest)
        )

        // Verify that vpToken is a VPTokenElement (single token) not VPTokenArray
        val pe = capturedResponse.captured as AuthorizationResponse.PresentationExchange
        assertTrue(pe.vpToken is VPTokenType.VPTokenElement)
    }

    @Test
    fun `constructVPResponse should create VP token array when multiple formats`() {
        mockkObject(ResponseModeBasedHandlerFactory)
        every { ResponseModeBasedHandlerFactory.get("direct_post") } returns mockResponseHandler

        val capturedResponse = slot<AuthorizationResponse>()
        every {
            mockResponseHandler.getAuthorizationResponse(
                dispatchInfo = any(),
                authorizationResponse = capture(capturedResponse),
                authorizationRequest = authorizationPresentationExchangeRequest
            )
        } returns mapOf("multiple" to "vp_tokens")

        // Setup internal state with multiple formats
        authorizationResponseHandler.constructUnsignedVPToken(
            selectedCredentials = selectedLdpVcCredentialsList + selectedMdocCredentialsList,
            authorizationRequest = authorizationPresentationExchangeRequest,
            responseUri = MOCK_VERIFIER_URL,
            nonce = walletNonce
        )

        authorizationResponseHandler.constructVPResponse(
            vpTokenSigningResults = listOf(
                VPTokenSigningResult(
                    id = RANDOM_UUID,
                    signedData = MOCK_SIGNED_DATA_1.toByteArray()
                )
            ),
            authorizationRequest = authorizationPresentationExchangeRequest,
            dispatchInfo = dispatchInfoFor(request = authorizationPresentationExchangeRequest)
        )

        // Verify that vpToken is a VPTokenArray (multiple tokens)
        val pe = capturedResponse.captured as AuthorizationResponse.PresentationExchange
        assertTrue(pe.vpToken is VPTokenType.VPTokenArray)
    }

    @Test
    fun `constructVPResponse should generate valid presentation submission`() {
        mockkObject(ResponseModeBasedHandlerFactory)
        every { ResponseModeBasedHandlerFactory.get("direct_post") } returns mockResponseHandler

        val capturedResponse = slot<AuthorizationResponse>()
        every {
            mockResponseHandler.getAuthorizationResponse(
                dispatchInfo = any(),
                authorizationResponse = capture(capturedResponse),
                authorizationRequest = authorizationPresentationExchangeRequest
            )
        } returns mapOf("presentation" to "submission")

        // Setup internal state
        authorizationResponseHandler.constructUnsignedVPToken(
            selectedCredentials = selectedLdpVcCredentialsList,
            authorizationRequest = authorizationPresentationExchangeRequest,
            responseUri = MOCK_VERIFIER_URL,
            nonce = walletNonce
        )

        authorizationResponseHandler.constructVPResponse(
            vpTokenSigningResults = listOf(
                VPTokenSigningResult(
                    id = RANDOM_UUID,
                    signedData = MOCK_SIGNED_DATA.toByteArray()
                )
            ),
            authorizationRequest = authorizationPresentationExchangeRequest,
            dispatchInfo = dispatchInfoFor(request = authorizationPresentationExchangeRequest)
        )

        val pe = capturedResponse.captured as AuthorizationResponse.PresentationExchange
        assertNotNull(pe.presentationSubmission.id)
        assertEquals(
            authorizationPresentationExchangeRequest.presentationDefinition.id,
            pe.presentationSubmission.definitionId
        )
        assertTrue(pe.presentationSubmission.descriptorMap.isNotEmpty())
    }

//    @Test
//    fun `constructUnsignedVPToken should flatten tokens with holderKeyReference and signatureAlgorithm`() {
//        unmockkConstructor(UnsignedVPTokenBuilder::class)
//        unmockkConstructor(UnsignedMdocVPTokenBuilder::class)
//        val authRequest = authorizationRequest.copy()
//        authRequest.presentationDefinition = deserializeAndValidate(
//            presentationDefinitionMapWithSdJwt,
//            PresentationDefinitionSerializer
//        )
//
//        val result = authorizationResponseHandler.constructUnsignedVPToken(
//            credentialsMap = credentialMap2,
//            holderId = holderId,
//            authorizationRequest = authRequest,
//            responseUri = responseUrl,
//            signatureSuite = signatureSuite,
//            nonce = walletNonce
//        )
//
//        val ldp = result.first { it.format == LDP_VC }
//        assertEquals(signatureSuite, ldp.signatureAlgorithm)
//        assertTrue(ldp.holderKeyReference.startsWith("did:"))
//        assertNotNull(ldp.dataToSign)
//
//        val mdoc = result.first { it.format == MSO_MDOC }
//        assertTrue(mdoc.holderKeyReference.length > 20)
//        assertEquals("ES256", mdoc.signatureAlgorithm)
//
//        val sdJwt = result.first { it.format == VC_SD_JWT }
//        assertTrue(sdJwt.holderKeyReference.startsWith("did:"))
//
//    }
//
//    @Test
//    fun `V2 roundtrip should flatten, sign and reconstruct VP correctly`() {
//
//
//        val responseModeHandler = mockk<ResponseModeBasedHandler>()
//
//        every {
//            ResponseModeBasedHandlerFactory.get(any())
//        } returns responseModeHandler
//
//        every {
//            responseModeHandler.getAuthorizationResponse(
//                any(),
//                any(),
//                any()
//            )
//        } returns mapOf("vp_token" to "mockVpToken")
//
//
//        unmockkConstructor(UnsignedMdocVPTokenBuilder::class)
//        unmockkConstructor(UnsignedVPTokenBuilder::class)
//
//        val authRequest = authorizationRequest.copy().apply {
//            presentationDefinition = deserializeAndValidate(
//                presentationDefinitionMapWithSdJwt,
//                PresentationDefinitionSerializer
//            )
//        }
//
//
//        val unsignedList = authorizationResponseHandler.constructUnsignedVPToken(
//            credentialsMap = credentialMap2,
//            holderId = holderId,
//            authorizationRequest = authRequest,
//            responseUri = responseUrl,
//            signatureSuite = signatureSuite,
//            nonce = walletNonce
//        )
//
//        assertTrue(unsignedList.isNotEmpty())
//
//
//        val signingResults = unsignedList.mapIndexed { i, token ->
//            VPTokenSigningResult(
//                signedData = "signature-$i"
//            )
//        }
//
//
//        val response = authorizationResponseHandler.constructVPResponseV2(
//            vpTokenSigningResults = signingResults,
//            authorizationRequest = authRequest
//        )
//
//        assertTrue(response.isNotEmpty())
//
//
//        val ldp = unsignedList.first { it.format == FormatType.LDP_VC }
//        assertEquals(signatureSuite, ldp.signatureAlgorithm)
//        assertTrue(ldp.holderKeyReference.isNotBlank())
//        assertTrue(ldp.dataToSign.isNotBlank())
//
//        val mdoc = unsignedList.filter { it.format == FormatType.MSO_MDOC }
//        assertTrue(mdoc.isNotEmpty())
//        assertTrue(mdoc.all { it.signatureAlgorithm in listOf("ES256", "EdDSA") })
//        assertTrue(mdoc.all { it.holderKeyReference.isNotBlank() })
//        assertTrue(mdoc.all { it.dataToSign.isNotBlank() })
//
//        val sd = unsignedList.filter {
//            it.format == FormatType.VC_SD_JWT || it.format == FormatType.DC_SD_JWT
//        }
//        assertTrue(sd.isNotEmpty())
//        assertTrue(sd.all { it.holderKeyReference.isNotBlank() })
//        assertTrue(sd.all { it.signatureAlgorithm.isNotBlank() })
//        assertTrue(sd.all { it.dataToSign.isNotBlank() })
//
//
//        assertEquals(unsignedList.size, signingResults.size)
//    }
//

    // ==================== DCQL Tests ====================

    private fun createDcqlAuthorizationRequest(
        state: String? = null
    ): AuthorizationDcqlRequest {
        return AuthorizationDcqlRequest(
            clientId = clientId,
            responseType = "vp_token",
            responseMode = "direct_post",
            responseUri = responseUrl,
            redirectUri = null,
            nonce = verifierNonce,
            walletNonce = walletNonce,
            state = state,
            clientMetadata = null,
            dcqlQuery = DCQLQuery(
                credentials = listOf(
                    CredentialQuery(
                        id = QUERY_SDJWT,
                        format = VC_SD_JWT.value,
                        meta = emptyMap(),
                        requireCryptographicHolderBinding = false
                    )
                )
            )
        )
    }

    private fun createDcqlAuthorizationRequestMultiFormat(
        state: String? = null
    ): AuthorizationDcqlRequest {
        return AuthorizationDcqlRequest(
            clientId = clientId,
            responseType = "vp_token",
            responseMode = "direct_post",
            responseUri = responseUrl,
            redirectUri = null,
            nonce = verifierNonce,
            walletNonce = walletNonce,
            state = state,
            clientMetadata = null,
            dcqlQuery = DCQLQuery(
                credentials = listOf(
                    CredentialQuery(
                        id = QUERY_SDJWT,
                        format = VC_SD_JWT.value,
                        requireCryptographicHolderBinding = false
                    ),
                    CredentialQuery(
                        id = QUERY_MDOC,
                        format = MSO_MDOC.value,
                        requireCryptographicHolderBinding = false
                    )
                )
            )
        )
    }

    private fun createDcqlAuthorizationRequestWithQuery(
        dcqlQuery: DCQLQuery,
        state: String? = null
    ): AuthorizationDcqlRequest {
        return AuthorizationDcqlRequest(
            clientId = clientId,
            responseType = "vp_token",
            responseMode = "direct_post",
            responseUri = responseUrl,
            redirectUri = null,
            nonce = verifierNonce,
            walletNonce = walletNonce,
            state = state,
            clientMetadata = null,
            dcqlQuery = dcqlQuery
        )
    }

    @Test
    fun `DCQL - should not construct unsigned VP tokens for SD-JWT when holder binding is not required`() {
        val dcqlRequest = createDcqlAuthorizationRequest()
        val selectedCredentials = mapOf(
            QUERY_SDJWT to listOf(
                Credential(VC_SD_JWT, sdJwtCredential1, CRED_1)
            )
        )

        val result = authorizationResponseHandler.constructUnsignedVPToken(
            selectedCredentials = selectedCredentials,
            authorizationRequest = dcqlRequest,
            responseUri = responseUrl,
            nonce = walletNonce
        )

        assertNotNull(result)
        assertTrue(result.isEmpty())
    }

    @Test
    fun `DCQL - should not construct unsigned VP tokens for multiple SD-JWT credentials when holder binding is not required`() {
        val dcqlRequest = createDcqlAuthorizationRequestWithQuery(
            DCQLQuery(
                credentials = listOf(
                    CredentialQuery(
                        id = QUERY_SDJWT,
                        format = VC_SD_JWT.value,
                        multiple = true,
                        requireCryptographicHolderBinding = false
                    )
                )
            )
        )
        val selectedCredentials = mapOf(
            QUERY_SDJWT to listOf(
                Credential(VC_SD_JWT, sdJwtCredential1, CRED_1),
                Credential(VC_SD_JWT, sdJwtCredential2, "cred-2")
            )
        )

        val result = authorizationResponseHandler.constructUnsignedVPToken(
            selectedCredentials = selectedCredentials,
            authorizationRequest = dcqlRequest,
            responseUri = responseUrl,
            nonce = walletNonce
        )

        assertNotNull(result)
        assertTrue(result.isEmpty())
    }

    @Test
    fun `DCQL - should construct unsigned VP tokens for LDP VC when selected credential satisfies query`() {
        val dcqlRequest = createDcqlAuthorizationRequestWithQuery(
            DCQLQuery(
                credentials = listOf(
                    CredentialQuery(
                        id = "query-ldp",
                        format = LDP_VC.value,
                        meta = mapOf("type_values" to listOf(listOf("InsuranceCredential"))),
                        requireCryptographicHolderBinding = false
                    )
                )
            )
        )
        val selectedCredentials = mapOf(
            "query-ldp" to listOf(
                Credential(LDP_VC, ldpCredential1, "cred-ldp")
            )
        )

        val result = authorizationResponseHandler.constructUnsignedVPToken(
            selectedCredentials = selectedCredentials,
            authorizationRequest = dcqlRequest,
            responseUri = responseUrl,
            nonce = walletNonce
        )

        assertNotNull(result)
        assertTrue(result.isNotEmpty())
        assertTrue(result.all { it.format == LDP_VC })
    }

    @Test
    fun `DCQL - should construct unsigned VP tokens for mdoc`() {
        val dcqlRequest = AuthorizationDcqlRequest(
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
                        id = QUERY_MDOC,
                        format = MSO_MDOC.value,
                        requireCryptographicHolderBinding = false
                    )
                )
            )
        )
        val selectedCredentials = mapOf(
            QUERY_MDOC to listOf(
                Credential(MSO_MDOC, mdocCredential, CRED_MDOC)
            )
        )

        val result = authorizationResponseHandler.constructUnsignedVPToken(
            selectedCredentials = selectedCredentials,
            authorizationRequest = dcqlRequest,
            responseUri = responseUrl,
            nonce = walletNonce
        )

        assertNotNull(result)
        assertTrue(result.isNotEmpty())
        assertTrue(result.all { it.format == MSO_MDOC })
    }

    @Test
    fun `DCQL - should construct unsigned VP tokens for mixed SD-JWT and mdoc`() {
        val dcqlRequest = createDcqlAuthorizationRequestMultiFormat()
        val selectedCredentials = mapOf(
            QUERY_SDJWT to listOf(
                Credential(VC_SD_JWT, sdJwtCredential1, CRED_SDJWT)
            ),
            QUERY_MDOC to listOf(
                Credential(MSO_MDOC, mdocCredential, CRED_MDOC)
            )
        )

        val result = authorizationResponseHandler.constructUnsignedVPToken(
            selectedCredentials = selectedCredentials,
            authorizationRequest = dcqlRequest,
            responseUri = responseUrl,
            nonce = walletNonce
        )

        assertNotNull(result)
        assertTrue(result.isNotEmpty())
        assertFalse(result.any { it.format == VC_SD_JWT })
        assertTrue(result.any { it.format == MSO_MDOC })
    }

    @Test
    fun `DCQL - should throw error when selected credentials is empty`() {
        val dcqlRequest = createDcqlAuthorizationRequest()

        val exception = assertFailsWith<VerifiablePresentationConstructionFailure> {
            authorizationResponseHandler.constructUnsignedVPToken(
                selectedCredentials = mapOf(),
                authorizationRequest = dcqlRequest,
                responseUri = responseUrl,
                nonce = walletNonce
            )
        }
        assertEquals("server_error", exception.errorCode)
        assertEquals(
            PRESENTATION_INTERNAL_ERROR_MESSAGE,
            exception.message
        )
        val cause = assertIs<InvalidData>(exception.cause)
        assertTrue(cause.message!!.contains("Empty credentials list"))
    }

    @Test
    fun `DCQL - should propagate identifier for SD-JWT and allow constructVPResponse`() {
        val dcqlRequest = createDcqlAuthorizationRequest(state = "test-state")
        val selectedCredentials = mapOf(
            QUERY_SDJWT to listOf(
                Credential(VC_SD_JWT, sdJwtCredential1, CRED_1)
            )
        )

        // Step 1: Construct unsigned VP tokens (DCQL path)
        val unsignedTokens = authorizationResponseHandler.constructUnsignedVPToken(
            selectedCredentials = selectedCredentials,
            authorizationRequest = dcqlRequest,
            responseUri = responseUrl,
            nonce = walletNonce
        )

        assertNotNull(unsignedTokens)
        assertTrue(unsignedTokens.isEmpty())

        // Step 2: Mock the response mode handler for constructVPResponse
        mockkObject(ResponseModeBasedHandlerFactory)
        every { ResponseModeBasedHandlerFactory.get("direct_post") } returns mockResponseHandler

        val capturedResponse = slot<AuthorizationResponse>()
        every {
            mockResponseHandler.getAuthorizationResponse(
                dispatchInfo = any(),
                authorizationResponse = capture(capturedResponse),
                authorizationRequest = any()
            )
        } returns mapOf("dcql_response" to "success")

        // Step 3: Construct VP response with signing results
        val signingResults = unsignedTokens.map {
            VPTokenSigningResult(id = it.id, signedData = "mock-dcql-signature".toByteArray())
        }

        val result = authorizationResponseHandler.constructVPResponse(
            vpTokenSigningResults = signingResults,
            authorizationRequest = dcqlRequest,
            dispatchInfo = dispatchInfoFor(request = dcqlRequest)
        )

        // Verify the response was constructed successfully
        assertEquals(mapOf("dcql_response" to "success"), result)

        // Verify it used DCQL path (AuthorizationResponse.Dcql)
        val dcqlResponse = capturedResponse.captured as AuthorizationResponse.Dcql
        assertNotNull(dcqlResponse.vpToken)
        assertEquals("test-state", dcqlResponse.state)
    }

    @Test
    fun `DCQL - should propagate identifier for multiple SD-JWT credentials and allow constructVPResponse`() {
        val dcqlRequest = AuthorizationDcqlRequest(
            clientId = clientId,
            responseType = "vp_token",
            responseMode = "direct_post",
            responseUri = responseUrl,
            redirectUri = null,
            nonce = verifierNonce,
            walletNonce = walletNonce,
            state = "multi-cred-state",
            clientMetadata = null,
            dcqlQuery = DCQLQuery(
                credentials = listOf(
                    CredentialQuery(
                        id = "query-sdjwt-1",
                        format = VC_SD_JWT.value,
                        requireCryptographicHolderBinding = false
                    ),
                    CredentialQuery(
                        id = "query-sdjwt-2",
                        format = VC_SD_JWT.value,
                        requireCryptographicHolderBinding = false
                    )
                )
            )
        )
        val selectedCredentials = mapOf(
            "query-sdjwt-1" to listOf(
                Credential(VC_SD_JWT, sdJwtCredential1, CRED_1)
            ),
            "query-sdjwt-2" to listOf(
                Credential(VC_SD_JWT, sdJwtCredential2, "cred-2")
            )
        )

        val unsignedTokens = authorizationResponseHandler.constructUnsignedVPToken(
            selectedCredentials = selectedCredentials,
            authorizationRequest = dcqlRequest,
            responseUri = responseUrl,
            nonce = walletNonce
        )

        assertNotNull(unsignedTokens)
        assertTrue(unsignedTokens.isEmpty())

        mockkObject(ResponseModeBasedHandlerFactory)
        every { ResponseModeBasedHandlerFactory.get("direct_post") } returns mockResponseHandler

        val capturedResponse = slot<AuthorizationResponse>()
        every {
            mockResponseHandler.getAuthorizationResponse(
                dispatchInfo = any(),
                authorizationResponse = capture(capturedResponse),
                authorizationRequest = any()
            )
        } returns mapOf("multi_dcql" to "success")

        val signingResults = unsignedTokens.map {
            VPTokenSigningResult(id = it.id, signedData = "mock-mixed-sig".toByteArray())
        }

        val result = authorizationResponseHandler.constructVPResponse(
            vpTokenSigningResults = signingResults,
            authorizationRequest = dcqlRequest,
            dispatchInfo = dispatchInfoFor(request = dcqlRequest)
        )

        assertEquals(mapOf("multi_dcql" to "success"), result)
        val dcqlResponse = capturedResponse.captured as AuthorizationResponse.Dcql
        assertNotNull(dcqlResponse.vpToken)
        assertTrue(dcqlResponse.vpToken.isNotEmpty())
    }

    @Test
    fun `DCQL - should propagate identifier for mixed SD-JWT and mdoc and allow constructVPResponse`() {
        val dcqlRequest = createDcqlAuthorizationRequestMultiFormat(state = "mixed-state")
        val selectedCredentials = mapOf(
            QUERY_SDJWT to listOf(
                Credential(VC_SD_JWT, sdJwtCredential1, CRED_SDJWT)
            ),
            QUERY_MDOC to listOf(
                Credential(MSO_MDOC, mdocCredential, CRED_MDOC)
            )
        )

        val unsignedTokens = authorizationResponseHandler.constructUnsignedVPToken(
            selectedCredentials = selectedCredentials,
            authorizationRequest = dcqlRequest,
            responseUri = responseUrl,
            nonce = walletNonce
        )

        assertNotNull(unsignedTokens)
        assertFalse(unsignedTokens.any { it.format == VC_SD_JWT })
        assertTrue(unsignedTokens.any { it.format == MSO_MDOC })

        mockkObject(ResponseModeBasedHandlerFactory)
        every { ResponseModeBasedHandlerFactory.get("direct_post") } returns mockResponseHandler

        val capturedResponse = slot<AuthorizationResponse>()
        every {
            mockResponseHandler.getAuthorizationResponse(
                dispatchInfo = any(),
                authorizationResponse = capture(capturedResponse),
                authorizationRequest = any()
            )
        } returns mapOf("mixed_dcql" to "success")

        val signingResults = unsignedTokens.map {
            VPTokenSigningResult(id = it.id, signedData = "mock-mixed-sig".toByteArray())
        }

        val result = authorizationResponseHandler.constructVPResponse(
            vpTokenSigningResults = signingResults,
            authorizationRequest = dcqlRequest,
            dispatchInfo = dispatchInfoFor(request = dcqlRequest)
        )

        assertEquals(mapOf("mixed_dcql" to "success"), result)
        val dcqlResponse = capturedResponse.captured as AuthorizationResponse.Dcql
        assertNotNull(dcqlResponse.vpToken)
        assertEquals("mixed-state", dcqlResponse.state)
    }

    @Test
    fun `DCQL - should handle null state in response`() {
        val dcqlRequest = createDcqlAuthorizationRequest(state = null)
        val selectedCredentials = mapOf(
            QUERY_SDJWT to listOf(
                Credential(VC_SD_JWT, sdJwtCredential1, CRED_1)
            )
        )

        val unsignedTokens = authorizationResponseHandler.constructUnsignedVPToken(
            selectedCredentials = selectedCredentials,
            authorizationRequest = dcqlRequest,
            responseUri = responseUrl,
            nonce = walletNonce
        )

        mockkObject(ResponseModeBasedHandlerFactory)
        every { ResponseModeBasedHandlerFactory.get("direct_post") } returns mockResponseHandler

        val capturedResponse = slot<AuthorizationResponse>()
        every {
            mockResponseHandler.getAuthorizationResponse(
                dispatchInfo = any(),
                authorizationResponse = capture(capturedResponse),
                authorizationRequest = any()
            )
        } returns mapOf("no_state" to "response")

        val signingResults = unsignedTokens.map {
            VPTokenSigningResult(
                id = it.id,
                signedData = MOCK_SIG.toByteArray()
            )  // Use the actual token ID
        }

        authorizationResponseHandler.constructVPResponse(
            vpTokenSigningResults = signingResults,
            authorizationRequest = dcqlRequest,
            dispatchInfo = dispatchInfoFor(request = dcqlRequest)
        )

        assertNull(capturedResponse.captured.state)
    }

    @Test
    fun `DCQL - should throw error for unsupported response type`() {
        val dcqlRequest = AuthorizationDcqlRequest(
            clientId = clientId,
            responseType = "code",
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
                        id = QUERY_SDJWT,
                        format = VC_SD_JWT.value,
                        requireCryptographicHolderBinding = false
                    )
                )
            )
        )
        val selectedCredentials = mapOf(
            QUERY_SDJWT to listOf(
                Credential(VC_SD_JWT, sdJwtCredential1, CRED_1)
            )
        )

        val unsignedTokens = authorizationResponseHandler.constructUnsignedVPToken(
            selectedCredentials = selectedCredentials,
            authorizationRequest = dcqlRequest,
            responseUri = responseUrl,
            nonce = walletNonce
        )

        val signingResults = unsignedTokens.map {
            VPTokenSigningResult(id = RANDOM_UUID, signedData = MOCK_SIG.toByteArray())
        }

        val exception = assertFailsWith<AuthorizationResponseConstructionFailure> {
            authorizationResponseHandler.constructVPResponse(
                vpTokenSigningResults = signingResults,
                authorizationRequest = dcqlRequest,
                dispatchInfo = dispatchInfoFor(request = dcqlRequest)
            )
        }
        assertEquals("server_error", exception.errorCode)
        assertEquals(
            AUTHORIZATION_RESPONSE_INTERNAL_ERROR_MESSAGE,
            exception.message
        )
        val cause = assertIs<InvalidData>(exception.cause)
        assertTrue(cause.message!!.contains("not supported"))
    }

    @Test
    fun `DCQL - should throw when vpTokenSigningResults is missing required formats`() {
        val dcqlRequest = createDcqlAuthorizationRequestMultiFormat()
        val selectedCredentials = mapOf(
            QUERY_SDJWT to listOf(
                Credential(VC_SD_JWT, sdJwtCredential1, CRED_SDJWT)
            ),
            QUERY_MDOC to listOf(
                Credential(MSO_MDOC, mdocCredential, CRED_MDOC)
            )
        )

        val unsignedTokens = authorizationResponseHandler.constructUnsignedVPToken(
            selectedCredentials = selectedCredentials,
            authorizationRequest = dcqlRequest,
            responseUri = responseUrl,
            nonce = walletNonce
        )

        // Only provide signing results for SD-JWT count, missing mdoc
        val sdJwtCount = unsignedTokens.count { it.format == VC_SD_JWT }
        val signingResults = (1..sdJwtCount).map {
            VPTokenSigningResult(id = RANDOM_UUID, signedData = MOCK_SIG.toByteArray())
        }

        assertFailsWith<Exception> {
            authorizationResponseHandler.constructVPResponse(
                vpTokenSigningResults = signingResults,
                authorizationRequest = dcqlRequest,
                dispatchInfo = dispatchInfoFor(request = dcqlRequest)
            )
        }
    }

    @Test
    fun `DCQL - constructAndSendAuthorizationResponseToVerifier should work end-to-end for SD-JWT`() {
        val dcqlRequest = createDcqlAuthorizationRequest(state = "e2e-state")
        val selectedCredentials = mapOf(
            QUERY_SDJWT to listOf(
                Credential(VC_SD_JWT, sdJwtCredential1, CRED_1)
            )
        )

        val unsignedTokens = authorizationResponseHandler.constructUnsignedVPToken(
            selectedCredentials = selectedCredentials,
            authorizationRequest = dcqlRequest,
            responseUri = responseUrl,
            nonce = walletNonce
        )

        every {
            mockResponseHandler.sendAuthorizationResponse(any(), any(), any())
        } returns NetworkResponse(
            200,
            "{\"redirect_uri\":\"https://verifier.com/callback\"}",
            mapOf()
        )

        val signingResults = unsignedTokens.map {
            VPTokenSigningResult(id = RANDOM_UUID, signedData = "mock-dcql-sig".toByteArray())
        }

        val result = authorizationResponseHandler.constructAndSendAuthorizationResponseToVerifier(
            authorizationRequest = dcqlRequest,
            vpTokenSigningResults = signingResults,
            dispatchInfo = dispatchInfoFor(request = dcqlRequest, responseUrl = responseUrl)
        )

        assertNotNull(result)
        assertEquals(200, result.statusCode)
        assertEquals("https://verifier.com/callback", result.redirectUri)
    }

    @Test
    fun `constructAuthorizationErrorResponse falls back to invalid_request when dispatch info is absent`() {
        val response = authorizationResponseHandler.constructAuthorizationErrorResponse(
            dispatchInfo = null,
            exception = InvalidVerifier("unknown client", "test"),
            walletNonce = walletNonce
        )

        assertEquals("invalid_request", response["error"])
        assertEquals(
            "Failed to send error to verifier: Response dispatch details are not set. Cannot send error to verifier.",
            response["error_description"]
        )
    }

    @Test
    fun `constructVPResponse rejects a request without dispatch info`() {
        authorizationResponseHandler.constructUnsignedVPToken(
            selectedCredentials = selectedLdpVcCredentialsList,
            authorizationRequest = authorizationPresentationExchangeRequest,
            responseUri = "https://mock-verifier.com",
            nonce = walletNonce
        )

        val exception = assertFailsWith<AuthorizationResponseConstructionFailure> {
            authorizationResponseHandler.constructVPResponse(
                vpTokenSigningResults = listOf(
                    VPTokenSigningResult(id = "random-uuid", signedData = "sig".toByteArray())
                ),
                authorizationRequest = authorizationPresentationExchangeRequest,
                dispatchInfo = null
            )
        }

        assertEquals(
            "Failed to send error to verifier: Response dispatch details are not set. Cannot construct VP response.",
            exception.cause?.message
        )
    }

    @Test
    fun `constructAndSendAuthorizationResponseToVerifier rejects a request without dispatch info`() {
        val exception = assertFailsWith<ErrorDispatchFailure> {
            authorizationResponseHandler.constructAndSendAuthorizationResponseToVerifier(
                authorizationRequest = authorizationPresentationExchangeRequest,
                vpTokenSigningResults = emptyList(),
                dispatchInfo = null
            )
        }

        assertOpenId4VPException(
            exception = exception,
            expectedMessage = "Failed to send error to verifier: Response dispatch details are not set. Cannot send authorization response to verifier.",
            expectedErrorCode = "error_dispatch_failure"
        )
    }
}



