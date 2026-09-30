package io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.mdoc

import io.mockk.spyk
import io.mockk.verify
import io.mosip.openID4VP.authorizationRequest.AuthorizationPresentationExchangeRequest
import io.mosip.openID4VP.authorizationRequest.deserializeAndValidate
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.PresentationDefinitionSerializer
import io.mosip.openID4VP.authorizationResponse.CredentialInputDescriptorMapping
import io.mosip.openID4VP.constants.FormatType.MSO_MDOC
import io.mosip.openID4VP.constants.SpecVersion
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions.InvalidData
import io.mosip.openID4VP.testData.clientId
import io.mosip.openID4VP.testData.mdocCredential
import io.mosip.openID4VP.testData.presentationDefinitionMap
import io.mosip.openID4VP.testData.responseUrl
import io.mosip.openID4VP.testData.verifierNonce
import io.mosip.openID4VP.testData.walletConfig
import io.mosip.openID4VP.testData.walletNonce
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
private const val INPUT_DESCRIPTOR_ID = "input-descriptor-id"
class UnsignedVPTokenBuilderJvmTest {

    private val testAuthorizationRequest = AuthorizationPresentationExchangeRequest(
        clientId = clientId,
        responseType = "vp_token",
        responseMode = "direct_post",
        presentationDefinition = deserializeAndValidate(
            presentationDefinitionMap,
            PresentationDefinitionSerializer
        ),
        responseUri = responseUrl,
        redirectUri = null,
        nonce = verifierNonce,
        state = null,
        walletNonce = walletNonce,
    )

    @Test
    fun `should use provided parameters correctly in token creation`() {
        val spyBuilder = spyk(
            UnsignedMdocVPTokenBuilder(
                authorizationRequest = testAuthorizationRequest,
                specVersion = SpecVersion.DRAFT_23,
                responseUri = responseUrl,
                mdocGeneratedNonce = walletNonce,
                walletConfig
            )
        )

        spyBuilder.build(listOf(CredentialInputDescriptorMapping(MSO_MDOC, mdocCredential, INPUT_DESCRIPTOR_ID)))
        verify {
            spyBuilder.build(match<List<CredentialInputDescriptorMapping>> {
                assertTrue(it.size == 1)
                val credentialInputDescriptorMapping = it.first()
                assertEquals(MSO_MDOC, credentialInputDescriptorMapping.format)
                assertEquals(mdocCredential, credentialInputDescriptorMapping.credential)
                (INPUT_DESCRIPTOR_ID == credentialInputDescriptorMapping.inputDescriptorId)
            })
        }
    }

    @Test
    fun `should throw exception when duplicate docType is found`() {
        val mdocCredentials = listOf(mdocCredential, mdocCredential)

        val exception = assertFailsWith<InvalidData> {
            UnsignedMdocVPTokenBuilder(
                authorizationRequest = testAuthorizationRequest,
                specVersion = SpecVersion.DRAFT_23,
                responseUri = responseUrl,
                mdocGeneratedNonce = walletNonce,
                walletConfig
            ).build(listOf(
                CredentialInputDescriptorMapping(MSO_MDOC, mdocCredential, "input-descriptor-id-1"),
                CredentialInputDescriptorMapping(MSO_MDOC, mdocCredential, "input-descriptor-id-2")
            ))
        }

        assertEquals("Duplicate Mdoc Credentials with same doctype found", exception.message)
    }

    @Test
    fun `should create token with correct structure and payload format`() {
        val (payload, _) = UnsignedMdocVPTokenBuilder(
            authorizationRequest = testAuthorizationRequest,
            specVersion = SpecVersion.DRAFT_23,
            responseUri = responseUrl,
            mdocGeneratedNonce = walletNonce,
            walletConfig
        ).build(listOf(CredentialInputDescriptorMapping(MSO_MDOC, mdocCredential, INPUT_DESCRIPTOR_ID)))

        @Suppress("UNCHECKED_CAST")
        val docTypeToDeviceAuthBytes = payload as? kotlin.collections.Map<String, ByteArray> ?: emptyMap()
        val identifier = docTypeToDeviceAuthBytes.keys.first()
        val authData = docTypeToDeviceAuthBytes[identifier]

        assertNotNull(identifier)
        assertFalse(identifier.isEmpty())

        assertNotNull(authData)

        // Check if the payload has data
        assertTrue(authData.isNotEmpty())
    }

    @Test
    fun `should create UnsignedMdocVPToken with valid input`() {
        val mdocCredentials = listOf(mdocCredential)

        val (payload, unsignedVPTokens) = UnsignedMdocVPTokenBuilder(
            authorizationRequest = testAuthorizationRequest,
            specVersion = SpecVersion.DRAFT_23,
            responseUri = responseUrl,
            mdocGeneratedNonce = walletNonce,
            walletConfig
        ).build(listOf(CredentialInputDescriptorMapping(MSO_MDOC, mdocCredential, INPUT_DESCRIPTOR_ID)))

        // Check vpTokenSigningPayload
        @Suppress("UNCHECKED_CAST")
        val identifierMap = payload as? kotlin.collections.Map<String, ByteArray>
        assertNotNull(identifierMap)
        assertEquals(1, identifierMap.size)
        assertTrue(unsignedVPTokens.isNotEmpty())
        assertEquals(1, unsignedVPTokens.size)
    }

}
