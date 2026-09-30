package io.mosip.openID4VP.authorizationResponse

import io.mosip.openID4VP.authorizationResponse.vpToken.VPTokenType
import io.mosip.openID4VP.authorizationResponse.vpToken.types.ldp.LdpVPToken
import io.mosip.openID4VP.authorizationResponse.vpToken.types.ldp.Proof
import io.mosip.openID4VP.testData.presentationSubmission
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.assertFalse
private const val TEST_LITERAL = "eryy....ewr"
private const val TEST_HOLDER_KEY = "did:example:holder#key-1"
class AuthorizationResponseTest {

    private val ldpVPToken = LdpVPToken(
        context = listOf("context"),
        type = listOf("type"),
        verifiableCredential = listOf("VC1"),
        id = "id",
        holder = "holder",
        proof = Proof(
            type = "type",
            created = "time",
            challenge = "challenge",
            domain = "domain",
            proofValue = TEST_LITERAL,
            proofPurpose = "authentication",
            verificationMethod = TEST_HOLDER_KEY
        )
    )

    private val vpToken = VPTokenType.VPTokenElement(
        ldpVPToken
    )

    private val authorizationResponse = AuthorizationResponse.PresentationExchange(
        presentationSubmission = presentationSubmission,
        vpToken = vpToken,
        state = "state"
    )

    @Test
    fun `toJsonEncodedMap should return correct map representation`() {
        val map = authorizationResponse.toJsonEncodedMap()
        assertEquals(3, map.size)
        assertTrue(map.containsKey("vp_token"))
        assertTrue(map.containsKey("presentation_submission"))
        assertTrue(map.containsKey("state"))
        assertEquals("state", map["state"])
    }

    @Test
    fun `toJsonEncodedMap should filter out null values`() {
        val responseWithNullState = AuthorizationResponse.PresentationExchange(
            presentationSubmission = presentationSubmission,
            vpToken = vpToken,
            state = null
        )
        val map = responseWithNullState.toJsonEncodedMap()
        assertEquals(2, map.size)
        assertTrue(map.containsKey("vp_token"))
        assertTrue(map.containsKey("presentation_submission"))
        assertFalse(map.containsKey("state"))
    }

    @Test
    fun `toMap should filter out null values`() {
        val responseWithNullState = AuthorizationResponse.PresentationExchange(
            presentationSubmission = presentationSubmission,
            vpToken = vpToken,
            state = null
        )
        val map = responseWithNullState.toMap()
        assertEquals(2, map.size)
        assertTrue(map.containsKey("vp_token"))
        assertTrue(map.containsKey("presentation_submission"))
        assertFalse(map.containsKey("state"))
    }

    @Test
    fun `toMap should return exact expected map`() {
        val expectedVpTokenMap = mapOf(
            "@context" to listOf("context"),
            "type" to listOf("type"),
            "verifiableCredential" to listOf("VC1"),
            "id" to "id",
            "holder" to "holder",
            "proof" to mapOf(
                "type" to "type",
                "created" to "time",
                "challenge" to "challenge",
                "domain" to "domain",
                "proofValue" to TEST_LITERAL,
                "proofPurpose" to "authentication",
                "verificationMethod" to TEST_HOLDER_KEY
            )
        )

        val expectedPresentationSubmissionMap = mapOf(
            "id" to "ps_id",
            "definition_id" to "client_id",
            "descriptor_map" to listOf(
                mapOf(
                    "id" to "input_descriptor_1",
                    "format" to "ldp_vp",
                    "path" to "$",
                    "path_nested" to mapOf(
                        "id" to "input_descriptor_1",
                        "format" to "ldp_vp",
                        "path" to "$.verifiableCredential[0]"
                    )
                )
            )
        )

        val expectedMap = mapOf(
            "vp_token" to expectedVpTokenMap,
            "presentation_submission" to expectedPresentationSubmissionMap,
            "state" to "state"
        )

        val actualMap = authorizationResponse.toMap()
        assertEquals(expectedMap, actualMap)
    }

    @Test
    fun `toMap should return objects for Dcql response`() {
        val dcqlResponse = AuthorizationResponse.Dcql(
            vpToken = mapOf("credential1" to listOf(ldpVPToken)),
            state = "state_123"
        )
        val expectedVpTokenMap = mapOf(
            "@context" to listOf("context"),
            "type" to listOf("type"),
            "verifiableCredential" to listOf("VC1"),
            "id" to "id",
            "holder" to "holder",
            "proof" to mapOf(
                "type" to "type",
                "created" to "time",
                "challenge" to "challenge",
                "domain" to "domain",
                "proofValue" to TEST_LITERAL,
                "proofPurpose" to "authentication",
                "verificationMethod" to TEST_HOLDER_KEY
            )
        )
        
        val expectedMap = mapOf(
            "vp_token" to mapOf("credential1" to listOf(expectedVpTokenMap)),
            "state" to "state_123"
        )

        val actualMap = dcqlResponse.toMap()
        assertEquals(expectedMap, actualMap)
    }
}

