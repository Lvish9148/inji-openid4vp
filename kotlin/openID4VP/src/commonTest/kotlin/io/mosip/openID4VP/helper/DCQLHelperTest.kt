package io.mosip.openID4VP.helper

import co.nstant.`in`.cbor.model.DataItem
import io.mockk.every
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import io.mockk.verify
import io.mosip.openID4VP.common.JsonLDProcessor
import io.mosip.openID4VP.common.MdocCredentialUtils
import io.mosip.openID4VP.common.MdocCredentialUtils.getMdocDocType
import io.mosip.openID4VP.common.decodeCbor
import io.mosip.openID4VP.common.decodeFromBase64Url
import io.mosip.openID4VP.common.resolveJWSAlgorithm
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.dcql.evaluator.DCQLEvaluationErrorCodes
import io.mosip.openID4VP.dcql.query.CredentialQuery
import io.mosip.openID4VP.dcql.query.CredentialSetQuery
import io.mosip.openID4VP.dcql.query.DCQLQuery
import io.mosip.openID4VP.dcql.evaluator.DCQLTestFixtures
import jakarta.json.Json as JakartaJson
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import java.util.Base64
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

private const val EMPLOYEE_CARD = "employee-card"
private const val EMPLOYEE_URL = "https://example.com/employee"
private const val SDJWT_1 = "sdjwt-1"
private const val MOBILE_ID = "mobile-id"
private const val MDL_DOCTYPE = "org.iso.18013.5.1.mDL"

class DCQLHelperTest {

    private val helper = DCQLHelper()


    @BeforeTest
    fun setUp() {
        mockkStatic(::decodeFromBase64Url)
        every { decodeFromBase64Url(any()) } answers {
            Base64.getUrlDecoder().decode(firstArg<String>())
        }

        mockkStatic(::decodeCbor)
        every { decodeCbor(any())} returns  DCQLTestFixtures.getDecodedMdoc()

        mockkObject(MdocCredentialUtils)
        every { getMdocDocType(any<Any>(), any()) } returns "org.iso.18013.5.1.mDL"
        every { getMdocDocType(any<DataItem>(), any()) } returns "org.iso.18013.5.1.mDL"

        mockkObject(JsonLDProcessor)
        every { JsonLDProcessor.expand(any()) } returns JakartaJson.createArrayBuilder().build()

        mockkStatic(::resolveJWSAlgorithm)
        every { resolveJWSAlgorithm(any(), any()) } returns "EdDSA"
    }

    @AfterTest
    fun tearDown() {
        unmockkAll()
    }

    @Test
    fun `should get matching credentials for single query`() {
        val query = DCQLQuery(
            credentials = listOf(
                CredentialQuery(
                    id = EMPLOYEE_CARD,
                    format = FormatType.VC_SD_JWT.value,
                    meta = mapOf("vct_values" to listOf(EMPLOYEE_URL))
                )
            )
        )

        val result = helper.getMatchingCredentials(listOf(DCQLTestFixtures.sdJwtCredential(SDJWT_1)), query)

        assertTrue(result.success)
        assertEquals(
            SDJWT_1,
            result.queryMatches[EMPLOYEE_CARD]?.matchingCredentials?.first()?.credentialId
        )
    }

    @Test
    fun `should return failure when credentials do not satisfy query`() {
        val query = DCQLQuery(
            credentials = listOf(
                CredentialQuery(
                    id = EMPLOYEE_CARD,
                    format = FormatType.VC_SD_JWT.value,
                    meta = mapOf("vct_values" to listOf(EMPLOYEE_URL))
                )
            )
        )

        val result = helper.getMatchingCredentials(
            listOf(DCQLTestFixtures.sdJwtCredential(SDJWT_1, vct = "https://example.com/other")),
            query
        )

        assertFalse(result.success)
        assertEquals(
            DCQLEvaluationErrorCodes.CRYPTOGRAPHIC_HOLDER_BINDING_OR_META_FILTER_MISMATCH.value,
            result.queryMatches[EMPLOYEE_CARD]?.failureReason
        )
    }

    @Test
    fun `should satisfy required credential set when all options are fulfilled`() {
        val query = DCQLQuery(
            credentials = listOf(
                CredentialQuery(
                    id = EMPLOYEE_CARD,
                    format = FormatType.VC_SD_JWT.value,
                    meta = mapOf("vct_values" to listOf(EMPLOYEE_URL))
                ),
                CredentialQuery(
                    id = MOBILE_ID,
                    format = FormatType.MSO_MDOC.value,
                    meta = mapOf("doctype_value" to MDL_DOCTYPE)
                )
            ),
            credentialSets = listOf(
                CredentialSetQuery(options = listOf(listOf(EMPLOYEE_CARD, MOBILE_ID)))
            )
        )

        val result = helper.getMatchingCredentials(
            listOf(
                DCQLTestFixtures.sdJwtCredential(SDJWT_1),
                DCQLTestFixtures.mdocCredential("mdoc-1")
            ),
            query
        )

        assertTrue(result.success)
        assertEquals(1, result.credentialSets.size)
        assertEquals(2, result.queryMatches.size)
    }

    @Test
    fun `should fail when required credential set option is not fulfilled`() {
        val query = DCQLQuery(
            credentials = listOf(
                CredentialQuery(
                    id = EMPLOYEE_CARD,
                    format = FormatType.VC_SD_JWT.value,
                    meta = mapOf("vct_values" to listOf(EMPLOYEE_URL))
                ),
                CredentialQuery(
                    id = MOBILE_ID,
                    format = FormatType.MSO_MDOC.value,
                    meta = mapOf("doctype_value" to MDL_DOCTYPE)
                )
            ),
            credentialSets = listOf(
                CredentialSetQuery(options = listOf(listOf(EMPLOYEE_CARD, MOBILE_ID)))
            )
        )

        val result = helper.getMatchingCredentials(
            listOf(DCQLTestFixtures.sdJwtCredential(SDJWT_1)),
            query
        )

        assertFalse(result.success)
    }

    @Test
    fun `should synthesize one required credential set per query when credentialSets is null`() {
        val query = DCQLQuery(
            credentials = listOf(
                CredentialQuery(
                    id = EMPLOYEE_CARD,
                    format = FormatType.VC_SD_JWT.value,
                    meta = mapOf("vct_values" to listOf(EMPLOYEE_URL))
                ),
                CredentialQuery(
                    id = MOBILE_ID,
                    format = FormatType.MSO_MDOC.value,
                    meta = mapOf("doctype_value" to MDL_DOCTYPE)
                )
            )
        )

        val result = helper.getMatchingCredentials(
            listOf(
                DCQLTestFixtures.sdJwtCredential(SDJWT_1),
                DCQLTestFixtures.mdocCredential("mdoc-1")
            ),
            query
        )

        assertEquals(2, result.credentialSets.size)
        assertEquals(listOf(listOf(EMPLOYEE_CARD)), result.credentialSets[0].options)
        assertTrue(result.credentialSets[0].required)
        assertEquals(listOf(listOf(MOBILE_ID)), result.credentialSets[1].options)
        assertTrue(result.credentialSets[1].required)
    }

    @Test
    fun `should succeed when optional credential set is not fulfilled`() {
        val query = DCQLQuery(
            credentials = listOf(
                CredentialQuery(
                    id = EMPLOYEE_CARD,
                    format = FormatType.VC_SD_JWT.value,
                    meta = mapOf("vct_values" to listOf(EMPLOYEE_URL))
                ),
                CredentialQuery(
                    id = MOBILE_ID,
                    format = FormatType.MSO_MDOC.value,
                    meta = mapOf("doctype_value" to MDL_DOCTYPE)
                )
            ),
            credentialSets = listOf(
                CredentialSetQuery(
                    options = listOf(listOf(EMPLOYEE_CARD, MOBILE_ID)),
                    required = false
                )
            )
        )

        val result = helper.getMatchingCredentials(
            listOf(DCQLTestFixtures.sdJwtCredential(SDJWT_1)),
            query
        )

        assertTrue(result.success)
    }

    // ---------------------------------------------------------------------------------------
    // VC 2.0 presentation readiness filtering
    // ---------------------------------------------------------------------------------------

    private fun ldpQuery(
        id: String = "employee-card",
        requireCryptographicHolderBinding: Boolean = true
    ) = CredentialQuery(
        id = id,
        format = FormatType.LDP_VC.value,
        requireCryptographicHolderBinding = requireCryptographicHolderBinding
    )

    private fun matchedIds(
        result: io.mosip.openID4VP.dcql.evaluator.MatchingCredentialsResult,
        queryId: String = "employee-card"
    ) = result.queryMatches[queryId]?.matchingCredentials?.map { it.credentialId }

    @Test
    fun `should match VC 2 credential with an eddsa holder key`() {
        every { resolveJWSAlgorithm(any(), any()) } returns "EdDSA"

        val result = helper.getMatchingCredentials(
            listOf(DCQLTestFixtures.ldpCredential("ldp-1")),
            DCQLQuery(credentials = listOf(ldpQuery()))
        )

        assertTrue(result.success)
        assertEquals(listOf("ldp-1"), matchedIds(result))
    }

    @Test
    fun `should match VC 2 credential with an es256 holder key`() {
        every { resolveJWSAlgorithm(any(), any()) } returns "ES256"

        val result = helper.getMatchingCredentials(
            listOf(DCQLTestFixtures.ldpCredential("ldp-1")),
            DCQLQuery(credentials = listOf(ldpQuery()))
        )

        assertTrue(result.success)
        assertEquals(listOf("ldp-1"), matchedIds(result))
    }

    @Test
    fun `should filter out VC 2 credential with an rsa holder key`() {
        every { resolveJWSAlgorithm(any(), any()) } returns "RS256"

        val result = helper.getMatchingCredentials(
            listOf(DCQLTestFixtures.ldpCredential("ldp-1")),
            DCQLQuery(credentials = listOf(ldpQuery()))
        )

        assertFalse(result.success)
        assertNull(matchedIds(result))
        assertEquals(
            DCQLEvaluationErrorCodes.CRYPTOGRAPHIC_HOLDER_BINDING_OR_META_FILTER_MISMATCH.value,
            result.queryMatches["employee-card"]?.failureReason
        )
    }

    @Test
    fun `should filter out VC 2 credential with an es384 holder key`() {
        every { resolveJWSAlgorithm(any(), any()) } returns "ES384"

        val result = helper.getMatchingCredentials(
            listOf(DCQLTestFixtures.ldpCredential("ldp-1")),
            DCQLQuery(credentials = listOf(ldpQuery()))
        )

        assertNull(matchedIds(result))
    }

    @Test
    fun `should filter out only the unsupported credential when several match the same query`() {
        every { resolveJWSAlgorithm("did:key:z6MkEd25519Holder", any()) } returns "EdDSA"
        every { resolveJWSAlgorithm("did:key:z6MkRsaHolder", any()) } returns "RS256"

        val result = helper.getMatchingCredentials(
            listOf(
                DCQLTestFixtures.ldpCredential("ldp-eddsa", holderId = "did:key:z6MkEd25519Holder"),
                DCQLTestFixtures.ldpCredential("ldp-rsa", holderId = "did:key:z6MkRsaHolder")
            ),
            DCQLQuery(credentials = listOf(ldpQuery()))
        )

        assertTrue(result.success)
        assertEquals(listOf("ldp-eddsa"), matchedIds(result))
    }

    @Test
    fun `should keep VC 1 credential with an rsa holder key`() {
        every { resolveJWSAlgorithm(any(), any()) } returns "RS256"

        val result = helper.getMatchingCredentials(
            listOf(
                DCQLTestFixtures.ldpCredential(
                    "ldp-1",
                    contexts = listOf(DCQLTestFixtures.VCDM_V1_CONTEXT)
                )
            ),
            DCQLQuery(credentials = listOf(ldpQuery()))
        )

        assertTrue(result.success)
        assertEquals(listOf("ldp-1"), matchedIds(result))
    }

    @Test
    fun `should not resolve the holder key when the query does not require holder binding`() {
        every { resolveJWSAlgorithm(any(), any()) } returns "RS256"

        val result = helper.getMatchingCredentials(
            listOf(DCQLTestFixtures.ldpCredential("ldp-1")),
            DCQLQuery(
                credentials = listOf(ldpQuery(requireCryptographicHolderBinding = false))
            )
        )

        assertTrue(result.success)
        assertEquals(listOf("ldp-1"), matchedIds(result))
        verify(exactly = 0) { resolveJWSAlgorithm(any(), any()) }
    }

    @Test
    fun `should leave non ldp credentials untouched`() {
        val result = helper.getMatchingCredentials(
            listOf(DCQLTestFixtures.sdJwtCredential("sdjwt-1")),
            DCQLQuery(
                credentials = listOf(
                    CredentialQuery(
                        id = "employee-card",
                        format = FormatType.VC_SD_JWT.value,
                        meta = mapOf("vct_values" to listOf("https://example.com/employee"))
                    )
                )
            )
        )

        assertTrue(result.success)
        assertEquals(listOf("sdjwt-1"), matchedIds(result))
        verify(exactly = 0) { resolveJWSAlgorithm(any(), any()) }
    }

    @Test
    fun `should keep credentials whose data model cannot be determined`() {
        every { resolveJWSAlgorithm(any(), any()) } returns "RS256"

        val result = helper.getMatchingCredentials(
            listOf(
                DCQLTestFixtures.ldpCredential("ldp-no-context", contexts = null),
                DCQLTestFixtures.ldpCredential(
                    "ldp-unknown-context",
                    contexts = listOf("https://example.com/v9")
                )
            ),
            DCQLQuery(credentials = listOf(ldpQuery()))
        )

        assertEquals(listOf("ldp-no-context", "ldp-unknown-context"), matchedIds(result))
    }

    @Test
    fun `should keep credentials whose holder key cannot be resolved`() {
        every { resolveJWSAlgorithm(any(), any()) } throws RuntimeException("did not resolvable")

        val result = helper.getMatchingCredentials(
            listOf(DCQLTestFixtures.ldpCredential("ldp-1", holderId = "did:example:holder")),
            DCQLQuery(credentials = listOf(ldpQuery()))
        )

        assertTrue(result.success)
        assertEquals(listOf("ldp-1"), matchedIds(result))
    }

    @Test
    fun `should resolve a repeated holder key only once across credential queries`() {
        every { resolveJWSAlgorithm(any(), any()) } returns "EdDSA"

        val result = helper.getMatchingCredentials(
            listOf(DCQLTestFixtures.ldpCredential("ldp-1")),
            DCQLQuery(
                credentials = listOf(ldpQuery("employee-card"), ldpQuery("contractor-card"))
            )
        )

        assertEquals(listOf("ldp-1"), matchedIds(result, "employee-card"))
        assertEquals(listOf("ldp-1"), matchedIds(result, "contractor-card"))
        verify(exactly = 1) { resolveJWSAlgorithm(any(), any()) }
    }
}
