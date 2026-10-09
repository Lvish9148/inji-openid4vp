package io.mosip.openID4VP.authorizationRequest.clientMetadata

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.CLIENT_METADATA
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.RESPONSE_MODE
import io.mosip.openID4VP.authorizationRequest.WalletConfig
import io.mosip.openID4VP.authorizationRequest.deserializeAndValidate
import io.mosip.openID4VP.common.getStringValue
import io.mosip.openID4VP.constants.SpecVersion
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.responseModeHandler.ResponseEncryptionSpecification
import io.mosip.openID4VP.responseModeHandler.ResponseModeBasedHandlerFactory

private val className = ClientMetadata::class.simpleName!!

private fun toStringAnyMap(raw: Map<*, *>): Map<String, Any> {
    return raw.entries.associate { (key, value) ->
        if (key !is String || value == null) {
            throw OpenID4VPExceptions.InvalidData(
                "client_metadata must be of type String or Map",
                className
            )
        }
        key to value
    }
}

enum class ClientMetadataSpecVersionHandler {
    V1, DRAFT_23;

    companion object {
        fun of(specVersion: SpecVersion): ClientMetadataSpecVersionHandler {
            return if (specVersion == SpecVersion.DRAFT_23) DRAFT_23 else V1
        }
    }

    fun parseAndValidate(
        authorizationRequestParameters: MutableMap<String, Any>,
        shouldValidateWithWalletMetadata: Boolean,
        walletConfig: WalletConfig
    ) {
        val clientMetadataRaw = authorizationRequestParameters[CLIENT_METADATA.value]

        if (clientMetadataRaw != null) {
            when (this) {
                DRAFT_23 -> {
                    val clientMetadata = when (clientMetadataRaw) {
                        is ClientMetadataDraft23 -> clientMetadataRaw
                        is String -> deserializeAndValidate(clientMetadataRaw, ClientMetadataDraft23Serializer)
                        is Map<*, *> -> deserializeAndValidate(
                            toStringAnyMap(clientMetadataRaw),
                            ClientMetadataDraft23Serializer
                        )
                        else -> throw OpenID4VPExceptions.InvalidData(
                            "client_metadata must be of type String or Map", className
                        )
                    }
                    authorizationRequestParameters[CLIENT_METADATA.value] = clientMetadata
                }
                V1 -> {
                    val clientMetadata = when (clientMetadataRaw) {
                        is ClientMetadata -> clientMetadataRaw
                        is String -> deserializeAndValidate(clientMetadataRaw, ClientMetadataSerializer)
                        is Map<*, *> -> deserializeAndValidate(
                            toStringAnyMap(clientMetadataRaw),
                            ClientMetadataSerializer
                        )
                        else -> throw OpenID4VPExceptions.InvalidData(
                            "client_metadata must be of type String or Map", className
                        )
                    }
                    authorizationRequestParameters[CLIENT_METADATA.value] = clientMetadata
                }
            }
        }
    }

    fun validateAsPerResponseModeAndGetResponseEncryptionSpecification(
        authorizationRequestParameters: Map<String, Any>,
        shouldValidateWithWalletMetadata: Boolean,
        walletConfig: WalletConfig
    ): ResponseEncryptionSpecification? {
        val responseMode = getStringValue(
            authorizationRequestParameters,
            RESPONSE_MODE.value
        ) ?: throw OpenID4VPExceptions.MissingInput(
            listOf(RESPONSE_MODE.value), "", className
        )

        val parsedClientMetadata = authorizationRequestParameters[CLIENT_METADATA.value]
        return when (this) {
            DRAFT_23 -> ResponseModeBasedHandlerFactory.get(responseMode)
                .validate(
                    parsedClientMetadata as? ClientMetadataDraft23,
                    walletConfig,
                    shouldValidateWithWalletMetadata
                )
            V1 -> ResponseModeBasedHandlerFactory.get(responseMode)
                .validate(
                    parsedClientMetadata as? ClientMetadata,
                    walletConfig,
                    shouldValidateWithWalletMetadata
                )
        }
    }
}
