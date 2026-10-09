package io.mosip.openID4VP.dcql.evaluator

import io.mosip.openID4VP.constants.FormatType

internal interface ProcessedCredential {
    val credentialId: String
    val credentialFormat: FormatType
}

internal interface ClaimsProcessedCredential : ProcessedCredential {
    val claims: Map<String, Any>
}

internal data class W3cProcessedCredential(
    override val credentialId: String,
    override val credentialFormat: FormatType,
    override val claims: Map<String, Any>
) : ClaimsProcessedCredential

internal data class MdocProcessedCredential(
    override val credentialId: String,
    override val credentialFormat: FormatType = FormatType.MSO_MDOC,
    val namespaces: Map<String, Map<String, Any>>
) : ProcessedCredential

internal data class SdJwtProcessedCredential(
    override val credentialId: String,
    override val credentialFormat: FormatType,
    override val claims: Map<String, Any>
) : ClaimsProcessedCredential