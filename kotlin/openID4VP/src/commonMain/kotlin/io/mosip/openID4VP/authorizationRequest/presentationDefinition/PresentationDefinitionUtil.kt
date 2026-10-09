package io.mosip.openID4VP.authorizationRequest.presentationDefinition

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.PRESENTATION_DEFINITION
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.PRESENTATION_DEFINITION_URI
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.RESPONSE_MODE
import io.mosip.openID4VP.authorizationRequest.deserializeAndValidate
import io.mosip.openID4VP.common.OpenID4VPErrorCodes
import io.mosip.openID4VP.common.getStringValue
import io.mosip.openID4VP.common.isValidUrl
import io.mosip.openID4VP.common.validate
import io.mosip.openID4VP.constants.HttpMethod
import io.mosip.openID4VP.constants.ResponseMode
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.networkManager.NetworkManagerClient.Companion.sendHTTPRequest
import io.mosip.openID4VP.networkManager.NetworkResponse

private val className = PresentationDefinition::class.simpleName!!

private fun toStringAnyMap(raw: Map<*, *>): Map<String, Any> {
    return raw.entries.associate { (key, value) ->
        val stringKey = key as? String
            ?: throw OpenID4VPExceptions.InvalidData(
                "presentation_definition must be of type String, Map, or PresentationDefinition",
                className
            )

        val nonNullValue = value
            ?: throw OpenID4VPExceptions.InvalidData(
                "presentation_definition must be of type String, Map, or PresentationDefinition",
                className
            )

        stringKey to nonNullValue
    }
}

fun parseAndValidatePresentationDefinition(
    authorizationRequestParameters: MutableMap<String, Any>,
    isPresentationDefinitionUriSupported: Boolean
) {
    val hasPresentationDefinition = authorizationRequestParameters.containsKey(PRESENTATION_DEFINITION.value)
    val hasPresentationDefinitionUri = authorizationRequestParameters.containsKey(PRESENTATION_DEFINITION_URI.value)
    val presentationDefinition: Any?

    when {
        hasPresentationDefinition && hasPresentationDefinitionUri -> {
            throw OpenID4VPExceptions.InvalidData(
                "Either presentation_definition or presentation_definition_uri request param can be provided but not both",
                className
            )
        }

        hasPresentationDefinition -> {
            presentationDefinition = authorizationRequestParameters[PRESENTATION_DEFINITION.value]
            validate(PRESENTATION_DEFINITION.value, presentationDefinition?.toString(), className)
        }

        hasPresentationDefinitionUri -> {
            if (!isPresentationDefinitionUriSupported) {
                throw OpenID4VPExceptions.InvalidData(
                    "presentation_definition_uri is not supported",
                    className,
                    OpenID4VPErrorCodes.INVALID_PRESENTATION_DEFINITION_REFERENCE
                )
            }

            val presentationDefinitionUri = getStringValue(
                authorizationRequestParameters,
                PRESENTATION_DEFINITION_URI.value
            )

            validate(PRESENTATION_DEFINITION_URI.value, presentationDefinitionUri, className)

            if (!isValidUrl(presentationDefinitionUri!!)) {
                throw OpenID4VPExceptions.InvalidData(
                    "presentation_definition_uri is not valid",
                    className,
                    OpenID4VPErrorCodes.INVALID_PRESENTATION_DEFINITION_URI
                )
            }

            val response: NetworkResponse
            try {
                response = sendHTTPRequest(
                    url = presentationDefinitionUri,
                    method = HttpMethod.GET
                )
                if(!response.isOk()){
                    throw OpenID4VPExceptions.InvalidData(
                        "Error while fetching presentation_definition from presentation_definition_uri: ${presentationDefinitionUri}, status code: ${response.statusCode} with body: ${response.body}",
                        className,
                        OpenID4VPErrorCodes.INVALID_PRESENTATION_DEFINITION_URI
                    )
                }
            } catch (e: Exception) {
                throw OpenID4VPExceptions.InvalidData(
                    "presentation_definition_uri could not be reached: $presentationDefinitionUri. Error: ${e.message}",
                    className,
                    OpenID4VPErrorCodes.INVALID_PRESENTATION_DEFINITION_URI
                )
            }

            val responseBody = response.body
            if (responseBody.isBlank()) {
                throw OpenID4VPExceptions.InvalidData(
                    "presentation_definition_uri response body is not valid",
                    className,
                    OpenID4VPErrorCodes.INVALID_PRESENTATION_DEFINITION_REFERENCE
                )
            }

            try {
                val pd = deserializeAndValidate(
                    responseBody,
                    PresentationDefinitionSerializer
                )
                presentationDefinition = pd
            } catch (e: Exception) {
                throw OpenID4VPExceptions.InvalidData(
                    "presentation_definition_uri did not contain valid presentation_definition",
                    className,
                    OpenID4VPErrorCodes.INVALID_PRESENTATION_DEFINITION_REFERENCE
                )
            }
        }

        else -> {
            throw OpenID4VPExceptions.InvalidData(
                "Either presentation_definition or presentation_definition_uri request param must be present",
                className
            )
        }
    }

    val presentationDefinitionObj = when (presentationDefinition) {
        is String -> deserializeAndValidate(
            presentationDefinition,
            PresentationDefinitionSerializer
        )

        is Map<*, *> -> deserializeAndValidate(
            toStringAnyMap(presentationDefinition),
            PresentationDefinitionSerializer
        )

        is PresentationDefinition -> presentationDefinition

        else -> throw OpenID4VPExceptions.InvalidData(
            "presentation_definition must be of type String, Map, or PresentationDefinition",
            className
        )
    }


    authorizationRequestParameters[PRESENTATION_DEFINITION.value] = presentationDefinitionObj

    val responseMode = getStringValue(
        authorizationRequestParameters,
        RESPONSE_MODE.value
    )!!

    validateResponseModeForMsoMdocFormat(presentationDefinitionObj, responseMode)
}




private fun validateResponseModeForMsoMdocFormat(presentationDefinitionObj: PresentationDefinition, responseMode: String) {
    val hasMsoMdocFormat = presentationDefinitionObj.format?.containsKey("mso_mdoc") ?: false ||
            presentationDefinitionObj.inputDescriptors.any {
                it.format?.containsKey("mso_mdoc") ?: false
            }

    if (hasMsoMdocFormat && (responseMode != ResponseMode.DIRECT_POST_JWT.value && responseMode != ResponseMode.IAR_POST_JWT.value &&
        responseMode != ResponseMode.IAE_POST_JWT.value)) {
        throw OpenID4VPExceptions.InvalidData("When mso_mdoc format is present in presentation definition, response_mode must be direct_post.jwt or iar-post.jwt or iae_post.jwt", className)

    }
}