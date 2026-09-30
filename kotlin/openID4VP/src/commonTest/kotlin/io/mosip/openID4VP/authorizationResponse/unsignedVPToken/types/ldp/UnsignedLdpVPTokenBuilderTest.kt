package io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp

import io.mockk.every
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import io.mosip.openID4VP.authorizationRequest.AuthorizationDcqlRequest
import io.mosip.openID4VP.authorizationRequest.AuthorizationPresentationExchangeRequest
import io.mosip.openID4VP.authorizationRequest.deserializeAndValidate
import io.mosip.openID4VP.dcql.query.CredentialQuery
import io.mosip.openID4VP.dcql.query.DCQLQuery
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.PresentationDefinitionSerializer
import io.mosip.openID4VP.authorizationResponse.CredentialInputDescriptorMapping
import io.mosip.openID4VP.authorizationResponse.CredentialToCredentialQueryIdMapping
import io.mosip.openID4VP.authorizationResponse.vpToken.types.ldp.LdpVPToken
import io.mosip.openID4VP.common.URDNA2015Canonicalization
import io.mosip.openID4VP.common.RDFC10Canonicalization
import io.mosip.openID4VP.common.decodeFromBase64Url
import io.mosip.openID4VP.common.encodeToBase64Url
import io.mosip.openID4VP.common.encodeToJsonString
import io.mosip.openID4VP.common.resolveJWSAlgorithm
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.constants.SignatureSuiteAlgorithm
import io.mosip.openID4VP.constants.SpecVersion
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.testData.assertOpenId4VPException
import io.mosip.openID4VP.common.OpenID4VPErrorCodes
import io.mosip.openID4VP.testData.ldpCredential1
import io.mosip.openID4VP.testData.ldpCredential2
import io.mosip.openID4VP.testData.presentationDefinitionMap
import io.mosip.openID4VP.testData.walletConfig
import kotlin.test.*
private const val MOCK_VERIFIER_RESPONSE = "https://mock-verifier.com/response"
private const val LDP_QUERY_1 = "ldp-query-1"
private const val LDP_QUERY_2 = "ldp-query-2"
private const val INPUT_DESCRIPTOR_ID1 = "input-descriptor-id1"
private const val INPUT_DESCRIPTOR_ID2 = "input-descriptor-id2"
class UnsignedLdpVPTokenBuilderTest {

    private val verifiableCredentials = listOf(ldpCredential1, ldpCredential2)
    private val id = "649d581c-f291-4969-9cd5-2c27385a348f"
    private val holder = "did:example:123456789"
    private val challenge = "test-challenge"
    private val domain = "test-domain.com"
    private val mockCanonicalizedData = "canonicalized-data"

    private val testAuthorizationRequest = AuthorizationPresentationExchangeRequest(
        clientId = domain,
        responseType = "vp_token",
        responseMode = "direct_post",
        presentationDefinition = deserializeAndValidate(presentationDefinitionMap, PresentationDefinitionSerializer),
        responseUri = MOCK_VERIFIER_RESPONSE,
        redirectUri = null,
        nonce = challenge,
        state = null,
        walletNonce = null,
    )

    private val testDcqlAuthorizationRequest = AuthorizationDcqlRequest(
        clientId = domain,
        responseType = "vp_token",
        responseMode = "direct_post",
        responseUri = MOCK_VERIFIER_RESPONSE,
        redirectUri = null,
        nonce = challenge,
        state = null,
        walletNonce = null,
        dcqlQuery = DCQLQuery(
            credentials = listOf(
                CredentialQuery(id = LDP_QUERY_1, format = "ldp_vc", requireCryptographicHolderBinding = true),
                CredentialQuery(id = LDP_QUERY_2, format = "ldp_vc", requireCryptographicHolderBinding = true),
            )
        )
    )

    private val testDcqlAuthorizationRequestNoBinding = AuthorizationDcqlRequest(
        clientId = domain,
        responseType = "vp_token",
        responseMode = "direct_post",
        responseUri = MOCK_VERIFIER_RESPONSE,
        redirectUri = null,
        nonce = challenge,
        state = null,
        walletNonce = null,
        dcqlQuery = DCQLQuery(
            credentials = listOf(
                CredentialQuery(id = "ldp-no-binding", format = "ldp_vc", requireCryptographicHolderBinding = false),
            )
        )
    )

    private val testDcqlAuthorizationRequestMultiple = AuthorizationDcqlRequest(
        clientId = domain,
        responseType = "vp_token",
        responseMode = "direct_post",
        responseUri = MOCK_VERIFIER_RESPONSE,
        redirectUri = null,
        nonce = challenge,
        state = null,
        walletNonce = null,
        dcqlQuery = DCQLQuery(
            credentials = listOf(
                CredentialQuery(id = LDP_QUERY_1, format = "ldp_vc", requireCryptographicHolderBinding = true),
                CredentialQuery(id = LDP_QUERY_2, format = "ldp_vc", requireCryptographicHolderBinding = true),
            )
        )
    )

    @BeforeTest
    fun setup() {
        mockkObject(URDNA2015Canonicalization)
        every { URDNA2015Canonicalization.canonicalize(any()) } returns mockCanonicalizedData
        mockkObject(RDFC10Canonicalization)
        every { RDFC10Canonicalization.canonicalizeDataIntegrity(any()) } returns ByteArray(64) { it.toByte() }

        mockkStatic(::resolveJWSAlgorithm)
        every { resolveJWSAlgorithm(any(), any()) } returns "EdDSA"

        mockkStatic(::decodeFromBase64Url)
        every { decodeFromBase64Url(any()) } answers {
            val input = firstArg<String>()
            java.util.Base64.getUrlDecoder().decode(input)
        }

        mockkStatic(::encodeToBase64Url)
        every { encodeToBase64Url(any()) } answers {
            val input = firstArg<ByteArray>()
            java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(input)
        }
    }

    @AfterTest
    fun tearDown() {
        unmockkAll()
    }

    @Test
    fun `test build(credentialInputDescriptorMappings) rejects an empty credential list`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            UnsignedLdpVPTokenBuilder(testAuthorizationRequest, SpecVersion.DRAFT_23, id, walletConfig)
                .build(emptyList<CredentialInputDescriptorMapping>())
        }
        assertOpenId4VPException(
            exception,
            "No credentials provided for LDP VP Token",
            OpenID4VPErrorCodes.INVALID_REQUEST
        )
    }

    @Test
    fun `test build(credentialInputDescriptorMappings) rejects a credential that is not a json object`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            UnsignedLdpVPTokenBuilder(testAuthorizationRequest, SpecVersion.DRAFT_23, id, walletConfig)
                .build(listOf(CredentialInputDescriptorMapping(FormatType.LDP_VC, "not-a-map", "input-1")))
        }
        assertOpenId4VPException(
            exception,
            "Credential is not a valid JSON object",
            OpenID4VPErrorCodes.INVALID_REQUEST
        )
    }

    @Test
    fun `test LdpVcToken serializes as the bare verifiable credential`() {
        val json = io.mosip.openID4VP.common.getObjectMapper()
            .writeValueAsString(LdpVcToken(mapOf("id" to "vc-1")))

        assertEquals("""{"id":"vc-1"}""", json)
    }

    @Test
    fun `test build(credentialInputDescriptorMappings) with JsonWebSignature2020`() {
        val mappings = listOf(
            CredentialInputDescriptorMapping(FormatType.LDP_VC, ldpCredential1, INPUT_DESCRIPTOR_ID1),
            CredentialInputDescriptorMapping(FormatType.LDP_VC, ldpCredential2, INPUT_DESCRIPTOR_ID2)
        )
        val builder = UnsignedLdpVPTokenBuilder(
            authorizationRequest = testAuthorizationRequest,
            specVersion = SpecVersion.DRAFT_23,
            id = id,
            walletConfig
        )
        val (payload, unsignedTokens) = builder.build(mappings)
        val vpPayloads = payload as Map<*, *>
        assertEquals(2, vpPayloads.size)
        val firstIdentifier = mappings.first().identifier
        assertNotNull(firstIdentifier)
        val vpPayload = vpPayloads[firstIdentifier] as LdpVPToken
        assertEquals(2, vpPayload.context.size)
        assertTrue(vpPayload.context.contains("https://www.w3.org/2018/credentials/v1"))
        assertTrue(vpPayload.context.contains("https://w3id.org/security/suites/jws-2020/v1"))
        assertEquals(listOf("VerifiablePresentation"), vpPayload.type)
        assertEquals(listOf(ldpCredential1), vpPayload.verifiableCredential)
        assertEquals(id, vpPayload.id)
        val (expectedHolder, _) = UnsignedLdpVPTokenBuilder.extractHolderAndSignatureSuite(ldpCredential1)
        val validatedExpectedHolder = UnsignedLdpVPTokenBuilder.validateHolderId(expectedHolder)
        assertEquals(validatedExpectedHolder, vpPayload.holder)
        val proof = vpPayload.proof
        assertNotNull(proof)
        assertEquals(SignatureSuiteAlgorithm.JsonWebSignature2020.value, proof?.type)
        assertEquals(null, proof?.created)
        assertEquals(validatedExpectedHolder, proof?.verificationMethod)
        assertEquals(domain, proof?.domain)
        assertEquals(challenge, proof?.challenge)
        assertEquals(2, unsignedTokens.size)
        val expectedHeaderMap = mapOf(
            "alg" to "EdDSA",
            "crit" to listOf("b64"),
            "b64" to false
        )
        val expectedHeaderJson = encodeToJsonString(expectedHeaderMap, "jwsHeader", "UnsignedLdpVPTokenBuilder")
        val expectedHeaderBase64Url = encodeToBase64Url(expectedHeaderJson.toByteArray(Charsets.UTF_8))
        val expectedRawPayloadBytes = java.util.Base64.getUrlDecoder().decode(mockCanonicalizedData)
        val expectedDataToSign = expectedHeaderBase64Url.toByteArray(Charsets.UTF_8) + byteArrayOf(0x2E.toByte()) + expectedRawPayloadBytes
        assertContentEquals(expectedDataToSign, unsignedTokens.first().dataToSign)
        assertEquals(FormatType.LDP_VC, unsignedTokens.first().format)
        assertEquals(validatedExpectedHolder, unsignedTokens.first().holderKeyReference)
        assertEquals("EdDSA", unsignedTokens.first().signatureAlgorithm)
    }

    @Test
    fun `test build preserves supported holder DIDs with optional fragments`() {
        val holderIds = listOf(
            "did:jwk:eyJrdHkiOiJFQyJ9",
            "did:jwk:eyJrdHkiOiJFQyJ9#0",
            "did:key:z6MkhWUE3JPyK6n4F6yA",
            "did:key:z6MkhWUE3JPyK6n4F6yA#z6MkhWUE3JPyK6n4F6yA",
            "did:web:example.com",
            "did:web:example.com#key-1"
        )
        val builder = UnsignedLdpVPTokenBuilder(
            authorizationRequest = testAuthorizationRequest,
            specVersion = SpecVersion.DRAFT_23,
            id = id,
            walletConfig
        )

        holderIds.forEach { holderId ->
            val credential = mapOf(
                "@context" to listOf("https://www.w3.org/2018/credentials/v1"),
                "credentialSubject" to mapOf("id" to holderId)
            )
            val mappings = listOf(
                CredentialInputDescriptorMapping(FormatType.LDP_VC, credential, "input-descriptor-id")
            )

            val (payloads, unsignedTokens) = builder.build(mappings)
            val vpPayload = payloads.values.single() as LdpVPToken

            assertEquals(holderId, vpPayload.holder)
            assertEquals(holderId, vpPayload.proof?.verificationMethod)
            assertEquals(holderId, unsignedTokens.single().holderKeyReference)
        }
    }

    @Test
    fun `test build rejects invalid holder identifiers`() {
        val invalidHolderIds = listOf(
            "base64url",
            "did:jwk:base64url#12",
            "did:key:z6MkhWUE3JPyK6n4F6yA#z6MkrDifferentFingerprint",
            "did:example:123"
        )
        val builder = UnsignedLdpVPTokenBuilder(
            authorizationRequest = testAuthorizationRequest,
            specVersion = SpecVersion.DRAFT_23,
            id = id,
            walletConfig
        )

        invalidHolderIds.forEach { holderId ->
            val credential = mapOf(
                "@context" to listOf("https://www.w3.org/2018/credentials/v1"),
                "credentialSubject" to mapOf("id" to holderId)
            )
            val mappings = listOf(
                CredentialInputDescriptorMapping(FormatType.LDP_VC, credential, "input-descriptor-id")
            )

            assertFailsWith<OpenID4VPExceptions.InvalidData> {
                builder.build(mappings)
            }
        }
    }

    @Test
    fun `VC 2 credential builds an eddsa Data Integrity presentation`() {
        val credential = mapOf<String, Any>(
            "@context" to listOf("https://www.w3.org/ns/credentials/v2"),
            "type" to listOf("VerifiableCredential"),
            "credentialSubject" to mapOf("id" to "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5In0#0")
        )
        val mappings = listOf(
            CredentialInputDescriptorMapping(FormatType.LDP_VC, credential, "vc2")
        )

        val (payloads, unsignedTokens) = UnsignedLdpVPTokenBuilder(
            testAuthorizationRequest,
            SpecVersion.DRAFT_23,
            id,
            walletConfig
        ).build(mappings)

        val payload = payloads[mappings.single().identifier] as LdpVPToken
        assertEquals(listOf("https://www.w3.org/ns/credentials/v2"), payload.context)
        assertEquals("DataIntegrityProof", payload.proof?.type)
        assertEquals("eddsa-rdfc-2022", payload.proof?.cryptosuite)
        assertEquals("authentication", payload.proof?.proofPurpose)
        assertEquals(
            "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5In0#0",
            payload.proof?.verificationMethod
        )
        assertContentEquals(ByteArray(64) { it.toByte() }, unsignedTokens.single().dataToSign)
    }

    @Test
    fun `VC 2 credential builds an ecdsa Data Integrity presentation`() {
        every { resolveJWSAlgorithm(any(), any()) } returns "ES256"
        val credential = mapOf<String, Any>(
            "@context" to listOf("https://www.w3.org/ns/credentials/v2"),
            "type" to listOf("VerifiableCredential"),
            "credentialSubject" to mapOf("id" to "did:jwk:eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2In0#0")
        )
        val mappings = listOf(
            CredentialInputDescriptorMapping(FormatType.LDP_VC, credential, "vc2")
        )

        val (payloads, unsignedTokens) = UnsignedLdpVPTokenBuilder(
            testAuthorizationRequest,
            SpecVersion.DRAFT_23,
            id,
            walletConfig
        ).build(mappings)

        val payload = payloads[mappings.single().identifier] as LdpVPToken
        assertEquals("DataIntegrityProof", payload.proof?.type)
        assertEquals("ecdsa-rdfc-2019", payload.proof?.cryptosuite)
        assertEquals("authentication", payload.proof?.proofPurpose)
        assertEquals("ES256", unsignedTokens.single().signatureAlgorithm)
        assertContentEquals(ByteArray(64) { it.toByte() }, unsignedTokens.single().dataToSign)
    }

    @Test
    fun `test buildDcql builds a Data Integrity presentation for a VC 2 credential`() {
        val credential = mapOf<String, Any>(
            "@context" to listOf("https://www.w3.org/ns/credentials/v2"),
            "type" to listOf("VerifiableCredential"),
            "credentialSubject" to mapOf("id" to "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5In0#0")
        )
        val mappings = mutableListOf(
            CredentialToCredentialQueryIdMapping(
                format = FormatType.LDP_VC,
                credential = credential,
                credentialQueryId = "ldp-query-1"
            )
        )

        val (payloads, unsignedTokens) = UnsignedLdpVPTokenBuilder(
            authorizationRequest = testDcqlAuthorizationRequest,
            specVersion = SpecVersion.V1,
            id = id,
            walletConfig
        ).build(mappings)

        val payload = payloads.values.single() as LdpVPToken
        assertEquals(listOf("https://www.w3.org/ns/credentials/v2"), payload.context)
        assertEquals("DataIntegrityProof", payload.proof?.type)
        assertEquals("eddsa-rdfc-2022", payload.proof?.cryptosuite)
        assertEquals("authentication", payload.proof?.proofPurpose)
        assertContentEquals(ByteArray(64) { it.toByte() }, unsignedTokens.single().dataToSign)
    }

    @Test
    fun `test buildDcql presents a VC 2 credential bare when holder binding is not required`() {
        val credential = mapOf<String, Any>(
            "@context" to listOf("https://www.w3.org/ns/credentials/v2"),
            "type" to listOf("VerifiableCredential"),
            "credentialSubject" to mapOf("id" to "did:jwk:eyJrdHkiOiJSU0EifQ")
        )
        every { resolveJWSAlgorithm(any(), any()) } returns "RS256"

        val mappings = mutableListOf(
            CredentialToCredentialQueryIdMapping(
                format = FormatType.LDP_VC,
                credential = credential,
                credentialQueryId = "ldp-no-binding"
            )
        )

        val (payloads, unsignedTokens) = UnsignedLdpVPTokenBuilder(
            authorizationRequest = testDcqlAuthorizationRequestNoBinding,
            specVersion = SpecVersion.V1,
            id = id,
            walletConfig
        ).build(mappings)

        // No proof is built, so an unsupported holder key is irrelevant on this path.
        assertEquals(0, unsignedTokens.size)
        assertTrue(payloads.values.single() is LdpVcToken)
    }

    @Test
    fun `VC 2 context must be the first entry in the credential context`() {
        val credential = mapOf<String, Any>(
            "@context" to listOf(
                "https://www.w3.org/2018/credentials/v1",
                "https://www.w3.org/ns/credentials/v2"
            ),
            "type" to listOf("VerifiableCredential"),
            "credentialSubject" to mapOf("id" to "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5In0#0")
        )

        val error = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            UnsignedLdpVPTokenBuilder(
                testAuthorizationRequest,
                SpecVersion.DRAFT_23,
                id,
                walletConfig
            ).build(listOf(CredentialInputDescriptorMapping(FormatType.LDP_VC, credential, "vc2")))
        }

        assertTrue(error.message!!.contains("VC 2.0 context must be the first @context entry"))
    }

    @Test
    fun `VC 2 credential rejects RSA holder key`() {
        every { resolveJWSAlgorithm(any(), any()) } returns "RS256"
        val credential = mapOf<String, Any>(
            "@context" to listOf("https://www.w3.org/ns/credentials/v2"),
            "type" to listOf("VerifiableCredential"),
            "credentialSubject" to mapOf("id" to "did:jwk:eyJrdHkiOiJSU0EifQ")
        )

        val error = assertFailsWith<OpenID4VPExceptions.UnsupportedVcdm2HolderKey> {
            UnsignedLdpVPTokenBuilder(
                testAuthorizationRequest,
                SpecVersion.DRAFT_23,
                id,
                walletConfig
            ).build(listOf(CredentialInputDescriptorMapping(FormatType.LDP_VC, credential, "vc2")))
        }

        assertEquals("access_denied", error.errorCode)
        assertTrue(
            error.message!!.contains("supports only Ed25519 and P-256 holder keys; found RS256")
        )
    }

    @Test
    fun `test build(credentialInputDescriptorMappings) canonicalization error handling`() {
        every { URDNA2015Canonicalization.canonicalize(any()) } throws RuntimeException("Canonicalization failed")
        val mappings = listOf(
            CredentialInputDescriptorMapping(FormatType.LDP_VC, ldpCredential1, INPUT_DESCRIPTOR_ID1),
            CredentialInputDescriptorMapping(FormatType.LDP_VC, ldpCredential2, INPUT_DESCRIPTOR_ID2)
        )
        val builder = UnsignedLdpVPTokenBuilder(
            authorizationRequest = testAuthorizationRequest,
            specVersion = SpecVersion.DRAFT_23,
            id = id,
            walletConfig
        )
        val exception = assertFailsWith<RuntimeException> {
            builder.build(mappings)
        }
        assertEquals("Canonicalization failed", exception.message)
    }

    @Test
    fun `test build(credentialInputDescriptorMappings) sets nestedPath correctly`() {
        val credentialInputDescriptorMappings = listOf(
            CredentialInputDescriptorMapping(FormatType.LDP_VC, ldpCredential1, INPUT_DESCRIPTOR_ID1),
            CredentialInputDescriptorMapping(FormatType.LDP_VC, ldpCredential2, INPUT_DESCRIPTOR_ID2)
        )
        val builder = UnsignedLdpVPTokenBuilder(
            authorizationRequest = testAuthorizationRequest,
            specVersion = SpecVersion.DRAFT_23,
            id = id,
            walletConfig
        )

        builder.build(credentialInputDescriptorMappings)

        assertEquals("$.verifiableCredential[0]", credentialInputDescriptorMappings[0].nestedPath)
        assertEquals("$.verifiableCredential[0]", credentialInputDescriptorMappings[1].nestedPath)
    }

    @Test
    fun `test buildDcql extracts holder and signature suite from credential`() {
        val mappings = mutableListOf(
            CredentialToCredentialQueryIdMapping(
                format = FormatType.LDP_VC,
                credential = ldpCredential1,
                credentialQueryId = LDP_QUERY_1
            )
        )
        val builder = UnsignedLdpVPTokenBuilder(
            authorizationRequest = testDcqlAuthorizationRequest,
            specVersion = SpecVersion.V1,
            id = id,
            walletConfig
        )
        val (payloads, unsignedTokens) = builder.build(mappings)

        assertEquals(1, unsignedTokens.size)
        assertEquals(FormatType.LDP_VC, unsignedTokens.first().format)
        val vpPayload = payloads.values.first() as? LdpVPToken
        assertEquals(SignatureSuiteAlgorithm.JsonWebSignature2020.value, vpPayload?.proof?.type)
        val (expectedHolder, _) = UnsignedLdpVPTokenBuilder.extractHolderAndSignatureSuite(ldpCredential1)
        assertEquals(expectedHolder, vpPayload?.holder)
        assertEquals(expectedHolder, vpPayload?.proof?.verificationMethod)
        assertEquals(expectedHolder, unsignedTokens.first().holderKeyReference)
        assertNotNull(mappings[0].identifier)
    }

    @Test
    fun `test buildDcql skips signing for non-holder-binding credential`() {
        val mappings = mutableListOf(
            CredentialToCredentialQueryIdMapping(
                format = FormatType.LDP_VC,
                credential = ldpCredential1,
                credentialQueryId = "ldp-no-binding"
            )
        )
        val builder = UnsignedLdpVPTokenBuilder(
            authorizationRequest = testDcqlAuthorizationRequestNoBinding,
            specVersion = SpecVersion.V1,
            id = id,
            walletConfig
        )
        val (payloads, unsignedTokens) = builder.build(mappings)

        assertEquals(0, unsignedTokens.size)
        assertEquals(1, payloads.size)
        assertTrue(payloads.values.first() is LdpVcToken)
        assertNotNull(mappings[0].identifier)
    }

    @Test
    fun `test buildDcql builds per-credential VP tokens`() {
        val mappings = mutableListOf(
            CredentialToCredentialQueryIdMapping(
                format = FormatType.LDP_VC,
                credential = ldpCredential1,
                credentialQueryId = LDP_QUERY_1
            ),
            CredentialToCredentialQueryIdMapping(
                format = FormatType.LDP_VC,
                credential = ldpCredential2,
                credentialQueryId = LDP_QUERY_2
            )
        )
        val builder = UnsignedLdpVPTokenBuilder(
            authorizationRequest = testDcqlAuthorizationRequestMultiple,
            specVersion = SpecVersion.V1,
            id = id,
            walletConfig
        )
        val (payloads, unsignedTokens) = builder.build(mappings)

        assertEquals(2, unsignedTokens.size)
        assertEquals(2, payloads.size)
        assertNotEquals(mappings[0].identifier, mappings[1].identifier)
    }

    @Test
    fun `test buildDcql throws for non-DCQL authorization request`() {
        val mappings = mutableListOf(
            CredentialToCredentialQueryIdMapping(
                format = FormatType.LDP_VC,
                credential = ldpCredential1,
                credentialQueryId = LDP_QUERY_1
            )
        )
        val builder = UnsignedLdpVPTokenBuilder(
            authorizationRequest = testAuthorizationRequest,
            specVersion = SpecVersion.DRAFT_23,
            id = id,
            walletConfig
        )
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            builder.build(mappings)
        }
        assertTrue(exception.message.contains("Expected AuthorizationDcqlRequest"))
    }

    @Test
    fun `test buildDcql throws for unknown credential query id`() {
        val mappings = mutableListOf(
            CredentialToCredentialQueryIdMapping(
                format = FormatType.LDP_VC,
                credential = ldpCredential1,
                credentialQueryId = "unknown-query-id"
            )
        )
        val builder = UnsignedLdpVPTokenBuilder(
            authorizationRequest = testDcqlAuthorizationRequest,
            specVersion = SpecVersion.V1,
            id = id,
            walletConfig
        )
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            builder.build(mappings)
        }
        assertTrue(exception.message.contains("No matching credential query found"))
    }

    @Test
    fun `test extractHolderAndSignatureSuite extracts correctly`() {
        val (holderId, suite) = UnsignedLdpVPTokenBuilder.extractHolderAndSignatureSuite(ldpCredential1)
        assertTrue(holderId.startsWith("did:jwk:"))
        assertEquals(SignatureSuiteAlgorithm.JsonWebSignature2020.value, suite)
    }

    @Test
    fun `test extractHolderAndSignatureSuite throws for invalid credential`() {
        assertFailsWith<OpenID4VPExceptions.InvalidData> {
            UnsignedLdpVPTokenBuilder.extractHolderAndSignatureSuite("not-a-map")
        }
    }

    @Test
    fun `test extractHolderAndSignatureSuite throws for missing credentialSubject`() {
        assertFailsWith<OpenID4VPExceptions.InvalidData> {
            UnsignedLdpVPTokenBuilder.extractHolderAndSignatureSuite(mapOf("type" to "VerifiableCredential"))
        }
    }

    @Test
    fun `test extractHolderAndSignatureSuite throws for missing holder id`() {
        assertFailsWith<OpenID4VPExceptions.InvalidData> {
            UnsignedLdpVPTokenBuilder.extractHolderAndSignatureSuite(
                mapOf("credentialSubject" to mapOf("name" to "test"))
            )
        }
    }

    @Test
    fun `test validateHolderId preserves supported DIDs with optional fragments`() {
        listOf(
            "did:jwk:eyJrdHkiOiJFQyJ9",
            "did:jwk:eyJrdHkiOiJFQyJ9#0",
            "did:key:z6MkhWUE3JPyK6n4F6yA",
            "did:key:z6MkhWUE3JPyK6n4F6yA#z6MkhWUE3JPyK6n4F6yA",
            "did:web:example.com",
            "did:web:example.com#key-1",
            "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IkhyZHZnYkh6SGdRcUkwdlVabG1YeF9TYmRKdkJacEc5WVdJMlFjRmV5SGciLCJ1c2UiOiJzaWcifQ#0"
        ).forEach { holderId ->
            assertEquals(holderId, UnsignedLdpVPTokenBuilder.validateHolderId(holderId))
        }
    }

    @Test
    fun `test validateHolderId accepts padded did jwk and returns original holder id`() {
        listOf(
            "did:jwk:base64url==",
            "did:jwk:eyJrdHkiOiJFQyIsInVzZSI6InNpZyIsImNydiI6IlAtMjU2IiwieCI6IjFqNUtiM3JXNXRaMjBRYW5tZ1pYTkJNQzFGOExQNGRjS1VwWm5ZQ2tESEkiLCJ5IjoiaUR6MlpCOHZkS0Y1U05fSkRReHVFT29JMHpQNGV6ZXN5WS13NHo1bTdHdyIsImFsZyI6IkVTMjU2In0="
        ).forEach { padded ->
            assertEquals(padded, UnsignedLdpVPTokenBuilder.validateHolderId(padded))
        }
    }

    @Test
    fun `test validateHolderId accepts padded did jwk with fragment and returns original holder id`() {
        val paddedDid = "did:jwk:eyJrdHkiOiJFQyIsInVzZSI6InNpZyIsImNydiI6IlAtMjU2IiwieCI6IjFqNUtiM3JXNXRaMjBRYW5tZ1pYTkJNQzFGOExQNGRjS1VwWm5ZQ2tESEkiLCJ5IjoiaUR6MlpCOHZkS0Y1U05fSkRReHVFT29JMHpQNGV6ZXN5WS13NHo1bTdHdyIsImFsZyI6IkVTMjU2In0=#0"
        assertEquals(paddedDid, UnsignedLdpVPTokenBuilder.validateHolderId(paddedDid))
    }

    @Test
    fun `test validateHolderId rejects non-DID and unsupported DID methods`() {
        listOf(
            "base64url",
            "base64url==",
            "did:jwk:base64url#12",
            "did:jwk:base64url#",
            "did:key:not-a-multibase-value",
            "did:key:z6MkhWUE3JPyK6n4F6yA#z6MkrDifferentFingerprint",
            "did:key:z6MkhWUE3JPyK6n4F6yA#",
            "did:example:123",
            "did:web:",
            "did:web:example.com#",
            "did:web:example.com#invalid fragment",
            "did:web:example.com#key-1#nested",
            "did:web:example%ZZcom"
        ).forEach { holderId ->
            assertFailsWith<OpenID4VPExceptions.InvalidData> {
                UnsignedLdpVPTokenBuilder.validateHolderId(holderId)
            }
        }
    }

}

