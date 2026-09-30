package io.mosip.openID4VP.authorizationResponse.vpToken

import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.VPTokenSigningResult
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions.InvalidData
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions.MissingInput
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

private const val TOKEN_1 = "token-1"
private const val KID_TOKEN_1 = "kid-token-1"
private const val UNSIGNED_DATA_1 = "unsigned-data-1"
private const val DUP_TOKEN = "dup-token"
private const val DUP_ID = "dup-id"

class VPTokenUtilsTest {

    @Test
    fun `getUnsignedVPToken should return token for matching identifier`() {
        val token = UnsignedVPToken(
            id = TOKEN_1,
            format = FormatType.VC_SD_JWT,
            holderKeyReference = KID_TOKEN_1,
            signatureAlgorithm = "ES256K",
            dataToSign = UNSIGNED_DATA_1.toByteArray()
        )

        val result = getUnsignedVPToken(
            unsignedVPTokens = listOf(token),
            identifier = TOKEN_1,
            className = "VPTokenUtilsTest"
        )

        assertEquals(TOKEN_1, result.id)
        assertEquals(FormatType.VC_SD_JWT, result.format)
        assertEquals(KID_TOKEN_1, result.holderKeyReference)
    }

    @Test
    fun `getUnsignedVPToken should throw InvalidData for missing identifier`() {
        val token = UnsignedVPToken(
            id = TOKEN_1,
            format = FormatType.VC_SD_JWT,
            holderKeyReference = KID_TOKEN_1,
            signatureAlgorithm = "ES256K",
            dataToSign = UNSIGNED_DATA_1.toByteArray()
        )

        val exception = assertFailsWith<InvalidData> {
            getUnsignedVPToken(
                unsignedVPTokens = listOf(token),
                identifier = "missing-token",
                className = "VPTokenUtilsTest"
            )
        }

        assertEquals(
            "Missing unsigned VP token for identifier missing-token",
            exception.message
        )
    }

    @Test
    fun `getUnsignedVPToken should throw InvalidData for duplicate identifier`() {
        val duplicateTokens = listOf(
            UnsignedVPToken(
                id = DUP_TOKEN,
                format = FormatType.VC_SD_JWT,
                holderKeyReference = "kid-1",
                signatureAlgorithm = "ES256K",
                dataToSign = UNSIGNED_DATA_1.toByteArray()
            ),
            UnsignedVPToken(
                id = DUP_TOKEN,
                format = FormatType.VC_SD_JWT,
                holderKeyReference = "kid-2",
                signatureAlgorithm = "ES256K",
                dataToSign = "unsigned-data-2".toByteArray()
            )
        )

        val exception = assertFailsWith<InvalidData> {
            getUnsignedVPToken(
                unsignedVPTokens = duplicateTokens,
                identifier = DUP_TOKEN,
                className = "VPTokenUtilsTest"
            )
        }

        assertEquals(
            "Duplicate unsigned VP token for identifier dup-token",
            exception.message
        )
    }

    @Test
    fun `getVPTokenSigningResult should throw InvalidData for duplicate identifier`() {
        val signingResults = listOf(
            VPTokenSigningResult(id = DUP_ID, signedData = "sig-1".toByteArray()),
            VPTokenSigningResult(id = DUP_ID, signedData = "sig-2".toByteArray())
        )

        val exception = assertFailsWith<InvalidData> {
            getVPTokenSigningResult(
                vpTokenSigningResults = signingResults,
                identifier = DUP_ID,
                className = "VPTokenUtilsTest"
            )
        }

        assertEquals(
            "Duplicate VP token signing result for credential identifier dup-id",
            exception.message
        )
    }

    @Test
    fun `getVPTokenSigningResult should throw MissingInput for unknown identifier`() {
        val signingResults = listOf(
            VPTokenSigningResult(id = "known-id", signedData = "sig-1".toByteArray())
        )

        val exception = assertFailsWith<MissingInput> {
            getVPTokenSigningResult(
                vpTokenSigningResults = signingResults,
                identifier = "unknown-id",
                className = "VPTokenUtilsTest"
            )
        }

        assertEquals(
            "Missing VP token signing result for credential identifier unknown-id",
            exception.message
        )
    }
}


