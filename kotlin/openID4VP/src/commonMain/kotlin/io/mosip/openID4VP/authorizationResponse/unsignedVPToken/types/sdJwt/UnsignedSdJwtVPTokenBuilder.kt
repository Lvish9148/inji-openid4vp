package io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.sdJwt

import io.mosip.openID4VP.authorizationRequest.AuthorizationDcqlRequest
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationRequest.WalletConfig
import io.mosip.openID4VP.authorizationResponse.CredentialInputDescriptorMapping
import io.mosip.openID4VP.authorizationResponse.CredentialToCredentialQueryIdMapping
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.vpToken.getMatchingCredentialQuery
import io.mosip.openID4VP.common.UUIDGenerator
import io.mosip.openID4VP.common.hashData
import io.mosip.openID4VP.common.resolveSdJwtKeyAndAlg
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.constants.SpecVersion
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions.InvalidData
import io.mosip.openID4VP.jwt.jws.JWSHandler
import java.util.Date

internal class UnsignedSdJwtVPTokenBuilder(
    override val authorizationRequest: AuthorizationRequest,
    override val specVersion: SpecVersion,
    override val walletConfig: WalletConfig
) : UnsignedVPTokenBuilder {

    companion object {
        private const val className = "UnsignedSdJwtVPTokenBuilder"
        private const val KEY_BINDING_JWT = "kb+jwt"
    }

    @JvmName("buildForPex")
    fun build(credentialInputDescriptorMappings: List<CredentialInputDescriptorMapping>): Pair<Map<String, Any>, List<UnsignedVPToken>> {
        val identifierToUnsignedKBJwt = mutableMapOf<String, String>()
        val unsignedVPTokens = mutableListOf<UnsignedVPToken>()

        credentialInputDescriptorMappings.forEach { credentialInputDescriptorMapping ->
            val uuid = UUIDGenerator.generateUUID()
            credentialInputDescriptorMapping.identifier = uuid
            val sdJwtCredential =
                credentialInputDescriptorMapping.credential as? String ?: throw InvalidData(
                    "SD-JWT credential is not a String",
                    className
                )

            val sdJwt = sdJwtCredential.split("~")[0]
            val sdJwtPayload = JWSHandler.extractDataJsonFromJws(sdJwt, JWSHandler.JwsPart.PAYLOAD)

            addUnsignedKBJwt(
                identifierToUnsignedKBJWT = identifierToUnsignedKBJwt,
                unsignedVPTokens = unsignedVPTokens,
                uuid = uuid,
                format = credentialInputDescriptorMapping.format,
                sdJwtCredential = sdJwtCredential,
                sdJwtPayload = sdJwtPayload,
                shouldAddCryptographicHolderBinding = { cnf -> cnf.isNotEmpty() }
            )
        }

        return Pair(identifierToUnsignedKBJwt, unsignedVPTokens)
    }

    override fun build(
        credentialToCredentialQueryIdMappings: MutableList<CredentialToCredentialQueryIdMapping>
    ): Pair<Map<String, Any>, List<UnsignedVPToken>> {
        val dcqlRequest = authorizationRequest as? AuthorizationDcqlRequest
            ?: throw InvalidData("Expected AuthorizationDcqlRequest for DCQL flow", className)

        val identifierToUnsignedKBJWT = mutableMapOf<String, String>()
        val unsignedVPTokens = mutableListOf<UnsignedVPToken>()

        credentialToCredentialQueryIdMappings.forEach { mapping ->
            val uuid = UUIDGenerator.generateUUID()
            mapping.identifier = uuid

            val matchedQuery = getMatchingCredentialQuery(dcqlRequest, mapping.credentialQueryId, className)

            val sdJwtCredential =
                mapping.credential as? String ?: throw InvalidData(
                    "SD-JWT credential is not a String",
                    className
                )

            val sdJwt = sdJwtCredential.split("~")[0]
            val sdJwtPayload = JWSHandler.extractDataJsonFromJws(sdJwt, JWSHandler.JwsPart.PAYLOAD)

            addUnsignedKBJwt(
                identifierToUnsignedKBJWT = identifierToUnsignedKBJWT,
                unsignedVPTokens = unsignedVPTokens,
                uuid = uuid,
                format = mapping.format,
                sdJwtCredential = sdJwtCredential,
                sdJwtPayload = sdJwtPayload,
                shouldAddCryptographicHolderBinding = { cnf ->
                    if (matchedQuery.requireCryptographicHolderBinding) {
                        if (cnf.isEmpty()) {
                            throw InvalidData(
                                "Holder binding is required for presentation but no cnf claim was present",
                                className
                            )
                        }
                        return@addUnsignedKBJwt true
                    }
                    return@addUnsignedKBJwt false
                }
            )
        }

        return Pair(identifierToUnsignedKBJWT, unsignedVPTokens)
    }

    private fun addUnsignedKBJwt(
        identifierToUnsignedKBJWT: MutableMap<String, String>,
        unsignedVPTokens: MutableList<UnsignedVPToken>,
        uuid: String,
        format: FormatType,
        sdJwtCredential: String,
        sdJwtPayload: Map<String, Any>,
        shouldAddCryptographicHolderBinding: (Map<String, Any>) -> Boolean
    ) {
        val confirmationKeyClaim = when (val cnf = sdJwtPayload["cnf"]) {
            is Map<*, *> -> cnf.entries
                .filter { it.key is String && it.value != null }
                .associate { (key, value) -> key as String to value as Any }
            else -> null
        }
        if (!shouldAddCryptographicHolderBinding(confirmationKeyClaim ?: emptyMap())) {
            return
        }

        val hasKid = confirmationKeyClaim?.keys?.contains("kid") == true
        val hasJwk = confirmationKeyClaim?.keys?.contains("jwk") == true

        if (!hasKid && !hasJwk) {
            throw UnsupportedOperationException("Unsupported cnf format, must contain 'kid' or 'jwk'")
        }

        if (hasKid) {
            confirmationKeyClaim["kid"] as? String
                ?: throw InvalidData("kid must be a string", className)
        }

        val (holderKeyReference, jwtSigningAlgorithm) = resolveSdJwtKeyAndAlg(
            sdJwtCredential,
            className
        )

        val jwtHeader = mapOf<String, Any>(
            "alg" to jwtSigningAlgorithm,
            "typ" to KEY_BINDING_JWT
        )

        val sdHashAlgorithm = sdJwtPayload["_sd_alg"] as? String ?: "SHA-256"
        val sdHash = hashData(sdJwtCredential, sdHashAlgorithm)

        val jwtPayload = mapOf(
            "iat" to (Date().time / 1000),
            "aud" to authorizationRequest.clientId,
            "nonce" to authorizationRequest.nonce,
            "sd_hash" to sdHash
        )

        val unsignedJwt = JWSHandler.createUnsignedJWS(jwtHeader, jwtPayload)
        identifierToUnsignedKBJWT[uuid] = unsignedJwt

        unsignedVPTokens.add(
            UnsignedVPToken(
                id = uuid,
                format = format,
                holderKeyReference = holderKeyReference,
                signatureAlgorithm = jwtSigningAlgorithm,
                dataToSign = unsignedJwt.toByteArray(Charsets.UTF_8)
            )
        )
    }
}
