package io.mosip.openID4VP.authorizationResponse.vpToken.types.mdoc

import io.mosip.openID4VP.authorizationResponse.CredentialInputDescriptorMapping
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken
import io.mosip.openID4VP.authorizationResponse.vpToken.types.sdJwt.SdJwtVPToken
import io.mosip.openID4VP.authorizationResponse.vpToken.types.sdJwt.SdJwtVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.VPTokenSigningResult
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.testData.sampleVcSdJwtWithNoHolderBinding
import io.mosip.openID4VP.testData.sdJwtCredential1
import io.mosip.openID4VP.testData.sdJwtCredential2
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
private const val ID_123 = "id-123"
private const val UUID_Z = "uuid-z"
private const val UUID_A = "uuid-a"
private const val UUID_1 = "uuid-1"
private const val UUID_2 = "uuid-2"

class SdJwtVPTokenBuilderJvmTest {

    private val uuid = "uuid-123"
    private val sampleSdJwt = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJkaWQ6ZXhhbXBsZToxMjMifQ.signature~disclosure1~disclosure2"
    private val unsignedKBJwt = "eyJhbGciOiJFUzI1NksifQ.eyJub25jZSI6Im5vbmNlIn0"
    private val kbJwtSignature = "dummy_signature".toByteArray()

    private fun b64url(data: ByteArray): String =
        java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(data)

    @Test
    fun `should build final SD-JWT VP Token successfully`() {
        val unsignedVPToken = UnsignedVPToken(
            id = uuid,
            format = FormatType.VC_SD_JWT,
            holderKeyReference = "kid",
            signatureAlgorithm = "ES256K",
            dataToSign = unsignedKBJwt.toByteArray(Charsets.UTF_8)
        )
        val vpTokenSigningResults = listOf(VPTokenSigningResult(
            id = uuid,
            signedData = kbJwtSignature
        ))
        val builder = SdJwtVPTokenBuilder()

        val element = CredentialInputDescriptorMapping(FormatType.VC_SD_JWT, sampleSdJwt, ID_123)
        element.identifier = uuid
        val (vpTokens, descriptorMaps, nextIndex) = builder.build(
            listOf(element),
            Pair(mapOf(uuid to unsignedKBJwt), listOf(unsignedVPToken)),
            vpTokenSigningResults,
            0
        )
        val expected = "$sampleSdJwt$unsignedKBJwt.${b64url(kbJwtSignature)}"

        val vpToken = sdJwtVPToken(vpTokens)
        assertEquals(expected, vpToken.value)
        assertEquals(1, descriptorMaps.size)
        assertEquals("[DescriptorMap(id=id-123, format=vc+sd-jwt, path=\$[0], pathNested=null)]", descriptorMaps.toString())
        assertEquals(1, nextIndex)
    }

    @Test
    fun `should throw MissingInput when KB-JWT signature is missing`() {
        val builder = SdJwtVPTokenBuilder()

        val exception = assertThrows(OpenID4VPExceptions.MissingInput::class.java) {
            builder.build(
                listOf(
                    CredentialInputDescriptorMapping(
                        FormatType.VC_SD_JWT,
                        sdJwtCredential1,
                        ID_123
                    ).apply { identifier = uuid }
                ),
                Pair(
                    mapOf(uuid to unsignedKBJwt),
                    listOf(
                        UnsignedVPToken(
                            uuid, FormatType.VC_SD_JWT, "kid", "ES256K", unsignedKBJwt.toByteArray()
                        )
                    )
                ),
                emptyList(),
                0
            )
        }

        assertEquals(
            "Missing VP token signing result for credential identifier uuid-123",
            exception.message
        )
    }

    @Test
    fun `should apply SD-JWT signatures in credential order when identifiers are not sorted`() {
        val signatureZ = "signature-z".toByteArray()
        val signatureA = "signature-a".toByteArray()
        val credentialInputDescriptorMappings = listOf(
            CredentialInputDescriptorMapping(FormatType.VC_SD_JWT, "credential-z~", "id-z").apply { identifier = UUID_Z },
            CredentialInputDescriptorMapping(FormatType.VC_SD_JWT, "credential-a~", "id-a").apply { identifier = UUID_A },
            CredentialInputDescriptorMapping(FormatType.VC_SD_JWT, "credential-m~", "id-m").apply { identifier = "uuid-m" },
        )
        val unsignedVPTokenResult = Pair(
            mapOf(
                UUID_Z to "unsigned-kb-jwt-z",
                UUID_A to "unsigned-kb-jwt-a"
            ),
            listOf(
                UnsignedVPToken(
                    UUID_Z,
                    FormatType.VC_SD_JWT,
                    "kid-z",
                    "ES256K",
                    "unsigned-kb-jwt-z".toByteArray(Charsets.UTF_8)
                ),
                UnsignedVPToken(
                    UUID_A,
                    FormatType.VC_SD_JWT,
                    "kid-a",
                    "ES256K",
                    "unsigned-kb-jwt-a".toByteArray(Charsets.UTF_8)
                )
            )
        )
        val vpTokenSigningResults = listOf(
            VPTokenSigningResult(id = UUID_A, signedData = signatureZ),
            VPTokenSigningResult(id = UUID_Z, signedData = signatureA)
        )

        val (vpTokens, descriptorMaps, nextRootIndex) = SdJwtVPTokenBuilder().build(
            credentialInputDescriptorMappings,
            unsignedVPTokenResult,
            vpTokenSigningResults,
            3
        )

        assertEquals("credential-z~unsigned-kb-jwt-z.c2lnbmF0dXJlLWE", vpTokens[0].value)
        assertEquals("credential-a~unsigned-kb-jwt-a.c2lnbmF0dXJlLXo", vpTokens[1].value)
        assertEquals("credential-m~", vpTokens[2].value)
        assertEquals(listOf("$[3]", "$[4]", "$[5]"), descriptorMaps.map { it.path })
        assertEquals(listOf("id-z", "id-a", "id-m"), descriptorMaps.map { it.id })
        assertEquals(6, nextRootIndex)
    }

    @Test
    fun `should return result accordingly when multiple SD-JWT credentials are provided`() {
        val sig1 = "aHR0cHM6Ly93M2lkLm9yZy9zZWN1cml0eS9zdWl0ZXMvandzLTIwMjAvdjE".toByteArray()
        val sig2 = "kb-jwt-signature-2".toByteArray()
        val credentialInputDescriptorMappings = listOf(
            CredentialInputDescriptorMapping(FormatType.VC_SD_JWT, sdJwtCredential2, ID_123).apply { identifier = UUID_1 },
            CredentialInputDescriptorMapping(FormatType.VC_SD_JWT, sdJwtCredential1, "id-456").apply { identifier = UUID_2 },
            CredentialInputDescriptorMapping(FormatType.VC_SD_JWT, sampleVcSdJwtWithNoHolderBinding, "id-456").apply { identifier = "uuid-3" },
        )
        val unsignedVPTokenResult = Pair(
            mapOf(
                UUID_1 to "unsigned-kb-jwt-1",
                UUID_2 to "unsigned-kb-jwt-2"
            ),
            listOf(
                UnsignedVPToken(
                    "uuid1",
                    FormatType.VC_SD_JWT,
                    "kid1",
                    "ES256K",
                    "unsigned-kb-jwt-1".toByteArray(Charsets.UTF_8)
                ),
                UnsignedVPToken(
                    "uuid2",
                    FormatType.VC_SD_JWT,
                    "kid2",
                    "ES256K",
                    "unsigned-kb-jwt-2".toByteArray(Charsets.UTF_8)
                )
            )
        )
        val vpTokenSigningResults = listOf(
            VPTokenSigningResult(id = UUID_1, signedData = sig1),
            VPTokenSigningResult(id = UUID_2, signedData = sig2)
        )

        val builder = SdJwtVPTokenBuilder()

        val (vpTokens, descriptorMaps, nextRootIndex) = builder.build(
            credentialInputDescriptorMappings,
            unsignedVPTokenResult,
            vpTokenSigningResults,
            0
        )

        assertEquals(3, vpTokens.size)
        assertEquals(3, descriptorMaps.size)
        assertEquals(3, nextRootIndex)
        assertTrue(vpTokens[0].value.contains("unsigned-kb-jwt-1.${b64url(sig1)}"))
        assertTrue(vpTokens[1].value.contains("unsigned-kb-jwt-2.${b64url(sig2)}"))
        assertEquals("[DescriptorMap(id=id-123, format=vc+sd-jwt, path=\$[0], pathNested=null), DescriptorMap(id=id-456, format=vc+sd-jwt, path=\$[1], pathNested=null), DescriptorMap(id=id-456, format=vc+sd-jwt, path=\$[2], pathNested=null)]", descriptorMaps.toString())
    }

    private fun sdJwtVPToken(vpTokens: List<SdJwtVPToken>): SdJwtVPToken {
        assertTrue(vpTokens.size == 1)
        val vpToken = vpTokens.first() as SdJwtVPToken
        return vpToken
    }
}

