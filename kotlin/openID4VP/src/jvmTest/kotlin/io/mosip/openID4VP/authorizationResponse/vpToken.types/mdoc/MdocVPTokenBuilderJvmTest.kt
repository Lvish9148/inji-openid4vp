package io.mosip.openID4VP.authorizationResponse.vpToken.types.mdoc

import co.nstant.`in`.cbor.CborDecoder
import co.nstant.`in`.cbor.model.Map
import co.nstant.`in`.cbor.model.UnicodeString
import co.nstant.`in`.cbor.model.Array
import io.mosip.openID4VP.authorizationResponse.CredentialInputDescriptorMapping
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.VPTokenSigningResult
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mockk.*
import io.mosip.openID4VP.common.cborArrayOf
import io.mosip.openID4VP.common.cborMapOf
import io.mosip.openID4VP.common.decodeFromBase64Url
import io.mosip.openID4VP.common.encodeCbor
import io.mosip.openID4VP.common.encodeToBase64Url
import io.mosip.openID4VP.common.getDecodedMdocCredential
import io.mosip.openID4VP.common.MdocCredentialUtils
import io.mosip.openID4VP.testData.mdocCredential
import kotlin.test.*
import co.nstant.`in`.cbor.model.Map as CborMap
private const val MDL_DOCTYPE = "org.iso.18013.5.1.mDL"
private const val ELC_DOCTYPE = "org.iso.18013.5.1.elc"
private const val TEST_SIGNATURE_DATA_BASE64 = "c2lnbmF0dXJlX2RhdGE="
class MdocVPTokenBuilderJvmTest {

    private val docType = MDL_DOCTYPE

    @BeforeTest
    fun setUp() {
        mockkObject(MdocCredentialUtils)
        every { MdocCredentialUtils.extractMdocKeyReferenceAndAlg(any(), any()) } returns Pair(
            "keyRef",
            "ES256"
        )

        // Mock getMdocDocTypeAndIssuerSigned to return proper structure for both credentials
        every { MdocCredentialUtils.getMdocDocTypeAndIssuerSigned(any(), any()) } answers {
            val cred = firstArg<Any>() as String
            val credBytes = decodeFromBase64Url(cred)

            // Determine docType based on credential content
            val docType = if (cred == mdocCredential) {
                "org.iso.18013.5.1.mDL"
            } else {
                "org.iso.18013.5.1.elc"
            }

            // Create a minimal issuerSigned structure
            val issuerSigned = CborMap().apply {
                put(UnicodeString("nameSpaces"), CborMap())
                put(UnicodeString("issuerAuth"), Array())
            }

            Triple(cred, docType, issuerSigned)
        }

        mockkStatic(::getDecodedMdocCredential)
        every { getDecodedMdocCredential(any()) } answers {
            val cred = firstArg<String>()
            val map = Map()
            // Use the credential to determine docType: first call returns mDL, second returns elc
            if (!cred.startsWith("om5")) { // mdocCredential from testData starts differently from encodeCbor output
                map.put(UnicodeString("docType"), UnicodeString(MDL_DOCTYPE))
            } else {
                map.put(UnicodeString("docType"), UnicodeString(ELC_DOCTYPE))
            }
            map
        }
    }

    @AfterTest
    fun tearDown() {
        clearAllMocks()
    }

    @Test
    fun `should decode base64 using JVM decoder`() {
        val input = "aGVsbG8=" // "hello"
        val decoded = decodeFromBase64Url(input)
        assertEquals("hello", decoded.toString(Charsets.UTF_8))

        val id = "random-uuid"
        val unsignedVPToken = UnsignedVPToken(
            id = id,
            format = FormatType.MSO_MDOC,
            holderKeyReference = "keyRef",
            signatureAlgorithm = "ES256",
            dataToSign = "deviceAuthBytes".toByteArray()
        )
        val vpTokenSigningResults = listOf(
            VPTokenSigningResult(
                id = id,
                signedData = TEST_SIGNATURE_DATA_BASE64.toByteArray()
            )
        )

        val (vpTokens, descriptorMaps, nextIndex) = MdocVPTokenBuilder().build(
            credentialInputDescriptorMappings = listOf(
                CredentialInputDescriptorMapping(
                    FormatType.MSO_MDOC,
                    mdocCredential,
                    MDL_DOCTYPE
                ).apply { identifier = id }
            ),
            unsignedVPTokenResult = Pair(
                mapOf(docType to "deviceAuthentication"),
                listOf(unsignedVPToken)
            ),
            vpTokenSigningResults = vpTokenSigningResults,
            rootIndex = 0
        )

        val vpToken = mdocVPToken(vpTokens)

        val decodedResult = decodeFromBase64Url(vpToken.base64EncodedDeviceResponse)
        val decodedCbor = CborDecoder(decodedResult.inputStream()).decode()[0] as Map

        assertEquals("1.0", decodedCbor[UnicodeString("version")].toString())
        assertEquals(0, decodedCbor[UnicodeString("status")].toString().toInt())
        assertNotNull(decodedCbor[UnicodeString("documents")])
        assertEquals(1, descriptorMaps.size)
        assertEquals(
            "[DescriptorMap(id=org.iso.18013.5.1.mDL, format=mso_mdoc, path=\$[0], pathNested=null)]",
            descriptorMaps.toString()
        )
        assertEquals(1, nextIndex)
    }

    @Test
    fun `should return token with multiple documents for multiple credentials`() {
        // Create a properly structured mdoc credential with issuerSigned containing the docType in MSO
        val mdocCredential2 = encodeToBase64Url(
            encodeCbor(
                cborMapOf(
                    "nameSpaces" to cborMapOf(),
                    "issuerAuth" to cborArrayOf()
                )
            )
        )

        val id = "random-uuid1"
        val id2 = "random-uuid2"
        val unsignedVPToken1 = UnsignedVPToken(
            id = id,
            format = FormatType.MSO_MDOC,
            holderKeyReference = "keyRef",
            signatureAlgorithm = "ES256",
            dataToSign = "deviceAuth1".toByteArray()
        )
        val unsignedVPToken2 = UnsignedVPToken(
            id = id2,
            format = FormatType.MSO_MDOC,
            holderKeyReference = "keyRef",
            signatureAlgorithm = "ES256",
            dataToSign = "deviceAuth2".toByteArray()
        )
        val vpTokenSigningResults = listOf(
            VPTokenSigningResult(
                id = id,
                signedData = TEST_SIGNATURE_DATA_BASE64.toByteArray()
            ),
            VPTokenSigningResult(
                id = id2,
                signedData = TEST_SIGNATURE_DATA_BASE64.toByteArray()
            )
        )

        val (vpTokens, descriptorMaps, nextIndex) = MdocVPTokenBuilder().build(
            credentialInputDescriptorMappings = listOf(
                CredentialInputDescriptorMapping(
                    FormatType.MSO_MDOC,
                    mdocCredential,
                    MDL_DOCTYPE
                ).apply { identifier = id },
                CredentialInputDescriptorMapping(
                    FormatType.MSO_MDOC,
                    mdocCredential2,
                    ELC_DOCTYPE
                ).apply { identifier = id2 }
            ),
            unsignedVPTokenResult = Pair(
                mapOf(
                    id to "deviceAuthentication2",
                    id2 to "deviceAuthentication1"
                ),
                listOf(unsignedVPToken1, unsignedVPToken2)
            ),
            vpTokenSigningResults = vpTokenSigningResults,
            rootIndex = 0
        )

        val vpToken = mdocVPToken(vpTokens)
        val decodedResult = decodeFromBase64Url(vpToken.base64EncodedDeviceResponse)
        val decodedCbor = CborDecoder(decodedResult.inputStream()).decode()[0] as CborMap

        val documents = decodedCbor[UnicodeString("documents")] as Array
        assertNotNull(documents)
        assertEquals(documents.dataItems.size, 2)

        assertEquals(1, nextIndex)
        assertEquals(
            "[DescriptorMap(id=org.iso.18013.5.1.mDL, format=mso_mdoc, path=\$[0], pathNested=null), DescriptorMap(id=org.iso.18013.5.1.elc, format=mso_mdoc, path=\$[0], pathNested=null)]",
            descriptorMaps.toString()
        )
    }

    @Test
    fun `should throw exception when device authentication signature is missing`() {
        val id = "random-uuid"
        val unsignedVPToken = UnsignedVPToken(
            id = id,
            format = FormatType.MSO_MDOC,
            holderKeyReference = "keyRef",
            signatureAlgorithm = "ES256",
            dataToSign = "deviceAuth1".toByteArray()
        )

        val exception = assertFailsWith<OpenID4VPExceptions.MissingInput> {
            MdocVPTokenBuilder().build(
                credentialInputDescriptorMappings = listOf(
                    CredentialInputDescriptorMapping(
                        FormatType.MSO_MDOC,
                        mdocCredential,
                        MDL_DOCTYPE
                    ).apply { identifier = id }
                ),
                unsignedVPTokenResult = Pair(
                    mapOf(id to "deviceAuthentication1"),
                    listOf(unsignedVPToken)
                ),
                vpTokenSigningResults = emptyList(),
                rootIndex = 0
            )
        }

        assertEquals(
            "Missing VP token signing result for credential identifier random-uuid",
            exception.message
        )
    }

    private fun mdocVPToken(vpTokens: List<MdocVPToken>): MdocVPToken {
        assertNotNull(vpTokens)
        assertEquals(vpTokens.size, 1)
        val vpToken = vpTokens.first()
        return vpToken
    }
}
