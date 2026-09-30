package io.mosip.openID4VP.testData

import io.mosip.openID4VP.authorizationRequest.AuthorizationPresentationExchangeRequest
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.CLIENT_ID
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.CLIENT_METADATA
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.NONCE
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.PRESENTATION_DEFINITION
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.PRESENTATION_DEFINITION_URI
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.REDIRECT_URI
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.REQUEST_URI
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.REQUEST_URI_METHOD
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.RESPONSE_MODE
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.RESPONSE_TYPE
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.RESPONSE_URI
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.STATE
import io.mosip.openID4VP.authorizationRequest.LdpVpFormatSupported
import io.mosip.openID4VP.authorizationRequest.VPFormatSupported
import io.mosip.openID4VP.authorizationRequest.Verifier
import io.mosip.openID4VP.authorizationRequest.WalletConfig
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadataDraft23Serializer
import io.mosip.openID4VP.authorizationRequest.clientMetadata.Jwk
import io.mosip.openID4VP.authorizationRequest.deserializeAndValidate
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.PresentationDefinitionSerializer
import io.mosip.openID4VP.authorizationResponse.AuthorizationResponse
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.DescriptorMap
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.PathNested
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.PresentationSubmission
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken
import io.mosip.openID4VP.authorizationResponse.vpToken.VPTokenType
import io.mosip.openID4VP.authorizationResponse.vpToken.types.ldp.LdpVPToken
import io.mosip.openID4VP.authorizationResponse.vpToken.types.ldp.Proof
import io.mosip.openID4VP.authorizationResponse.vpToken.types.mdoc.MdocVPToken
import io.mosip.openID4VP.common.convertJsonToMap
import io.mosip.openID4VP.common.hexToByteArray
import kotlin.OptIn
import kotlin.ExperimentalStdlibApi
import io.mosip.openID4VP.constants.ClientIdPrefix
import io.mosip.openID4VP.constants.EncryptionAlgorithm
import io.mosip.openID4VP.constants.EncryptionMethod
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.constants.ProofType
import io.mosip.openID4VP.constants.SignatureAlgorithm
import io.mosip.openID4VP.constants.SpecVersion
import io.mosip.openID4VP.constants.VPFormatType
import java.security.PublicKey
private const val RANDOM_UUID = "random-uuid"
private const val TYPE_PATH = "$.type"
private const val MOCK_VERIFIER = "https://mock-verifier.com"
private const val TEST_KEY_1 = "VbRRB/LTxLiXmVNZuyMO8A=="
private const val TEST_KEY_2 = "bMHvX1HGhbh8zqlSWf/fuQ=="

const val requestUrl = "https://mock-verifier.com/verifier/get-auth-request-obj"
const val responseUrl = "https://mock-verifier.com/response-uri"
const val didUrl = "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs"
const val mdocCredential =
    "omdkb2NUeXBldW9yZy5pc28uMTgwMTMuNS4xLm1ETGxpc3N1ZXJTaWduZWSiamlzc3VlckF1dGiEQ6EBJqEYIVkCADCCAfwwggGjAhQF2zbegdWq1XHLmdrVZZIORS_efDAKBggqhkjOPQQDAjCBgDELMAkGA1UEBhMCSU4xCzAJBgNVBAgMAktBMRIwEAYDVQQHDAlCQU5HQUxPUkUxDjAMBgNVBAoMBUlJSVRCMQwwCgYDVQQLDANEQ1MxEDAOBgNVBAMMB0NFUlRJRlkxIDAeBgkqhkiG9w0BCQEWEW1vc2lwcWFAZ21haWwuY29tMB4XDTI1MDIxMjEyMzE1N1oXDTI2MDIxMjEyMzE1N1owgYAxCzAJBgNVBAYTAklOMQswCQYDVQQIDAJLQTESMBAGA1UEBwwJQkFOR0FMT1JFMQ4wDAYDVQQKDAVJSUlUQjEMMAoGA1UECwwDRENTMRAwDgYDVQQDDAdDRVJUSUZZMSAwHgYJKoZIhvcNAQkBFhFtb3NpcHFhQGdtYWlsLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABAcZXrsgNSABzg9o_dNKu6S2pXuJ3hgYlX162Ex56IUGDJZP_IlRCrEQPHZSSl53DwlpL4iHisASqFaRQiXAtqkwCgYIKoZIzj0EAwIDRwAwRAIgGI6B63QccJQ4B84hRjRGlRURJ5SSNTuf74w-nE8zqRACIA3diiD3VCA5G6joGeTSX-Xx79shhDrCmUHuj3Lk5uL1WQJR2BhZAkymZ3ZlcnNpb25jMS4wb2RpZ2VzdEFsZ29yaXRobWdTSEEtMjU2Z2RvY1R5cGV1b3JnLmlzby4xODAxMy41LjEubURMbHZhbHVlRGlnZXN0c6Fxb3JnLmlzby4xODAxMy41LjGoAlggwUwjgySYg2DOdGY4nNo0iwMhvWfX461qVPqRfzOSkLAGWCAqcNYwEHbJmU1HDkOtxjK_X-L6wsApZp6M68hP0409vANYIHvJF0gsS8tMyfvTgmIeEeLIL-wx50tcOjkJNGJUB7eaAVggeYDGTfx8w7Sz2hIQvkZ1QhtrXskhDjZkS_cgN6HP18oEWCBeZlkW29iqUBLxAFlOfHrz5qXioXKKaoyEEYI96YyKvwBYIIlDF4uT1D3MLGPsLL-kVBP0SHyxAYcAVf9SLYLUJUUgB1ggFuI0cmV1WwSJGv5VxI5a7Dsm6fIqr2MeIDBmYjIlZ0oFWCA88kOo8KNGtCpl2XH5CXMcgoE6D_fag9xjmPoLUcpgpG1kZXZpY2VLZXlJbmZvoWlkZXZpY2VLZXmkAQIgASFYIHXTzp8Von2hagU3QkJVjUyInx0bVtJ_jBEGgdg9i8_xIlggcu55Afxk6PuLoyhqtNVMr_C2H2tumM4fKr-fthKcg0dsdmFsaWRpdHlJbmZvo2ZzaWduZWTAdDIwMjUtMDQtMzBUMTE6NTQ6MzdaaXZhbGlkRnJvbcB0MjAyNS0wNC0zMFQxMTo1NDozN1pqdmFsaWRVbnRpbMB0MjAyNy0wNC0zMFQxMTo1NDozN1pYQMU-ji8KQVOtW-G8YJWadw4_ZSRpb56M4Xv8MUg9ivRqV3VIJpJ5tB55onmNLrVOao0OunClNsBP7iNvX8P3d-BqbmFtZVNwYWNlc6Fxb3JnLmlzby4xODAxMy41LjGI2BhYWKRoZGlnZXN0SUQCZnJhbmRvbVBthSy1vmphqpoMYRe9Z0PncWVsZW1lbnRJZGVudGlmaWVyamlzc3VlX2RhdGVsZWxlbWVudFZhbHVlajIwMjUtMDQtMzDYGFhZpGhkaWdlc3RJRAZmcmFuZG9tUNyXhXOZjmheiFyzYfhsl0ZxZWxlbWVudElkZW50aWZpZXJrZXhwaXJ5X2RhdGVsZWxlbWVudFZhbHVlajIwMzAtMDQtMzDYGFifpGhkaWdlc3RJRANmcmFuZG9tUCC-v7ARALJ2VFcYww9AbMhxZWxlbWVudElkZW50aWZpZXJyZHJpdmluZ19wcml2aWxlZ2VzbGVsZW1lbnRWYWx1ZXhIe2lzc3VlX2RhdGU9MjAyNS0wNC0zMCwgdmVoaWNsZV9jYXRlZ29yeV9jb2RlPUEsIGV4cGlyeV9kYXRlPTIwMzAtMDQtMzB92BhYXaRoZGlnZXN0SUQBZnJhbmRvbVDjoYj_8RBZ62-85iZV371vcWVsZW1lbnRJZGVudGlmaWVyb2RvY3VtZW50X251bWJlcmxlbGVtZW50VmFsdWVqOTI2MTQ4MTAyNNgYWFWkaGRpZ2VzdElEBGZyYW5kb21Qg7iWcNbZ-b9S2D3u3Av2YnFlbGVtZW50SWRlbnRpZmllcm9pc3N1aW5nX2NvdW50cnlsZWxlbWVudFZhbHVlYklO2BhYWKRoZGlnZXN0SUQAZnJhbmRvbVAFg1zMFq1oLYxHiib0UCeYcWVsZW1lbnRJZGVudGlmaWVyamJpcnRoX2RhdGVsZWxlbWVudFZhbHVlajE5OTQtMTEtMDbYGFhUpGhkaWdlc3RJRAdmcmFuZG9tUElZm1bdU7M1GlcrQPJ_ctNxZWxlbWVudElkZW50aWZpZXJqZ2l2ZW5fbmFtZWxlbGVtZW50VmFsdWVmSm9zZXBo2BhYVaRoZGlnZXN0SUQFZnJhbmRvbVB_NHtdmXkWLPqVnSgypGGWcWVsZW1lbnRJZGVudGlmaWVya2ZhbWlseV9uYW1lbGVsZW1lbnRWYWx1ZWZBZ2F0aGE="
val ldpCredential1 =
    convertJsonToMap(
        "{\"id\":\"did:rcw:38d51ff1-c55d-40be-af56-c3f30aaa81d4\",\"type\":[\"VerifiableCredential\",\"InsuranceCredential\"],\"proof\":{\"type\":\"Ed25519Signature2020\",\"created\":\"2025-05-12T10:51:03Z\",\"proofValue\":\"z62rZ8pWHi1PmkGYzZmgF8sQoLCPwwfvXYmSsC7P6KoaVyAoDv1SRi1VomcQqSv41HvkHKrHUfpJX3K3ZU9G1rVoh\",\"proofPurpose\":\"assertionMethod\",\"verificationMethod\":\"did:web:api.collab.mosip.net:identity-service:56de166e-0e2f-4734-b8e7-be42b3117d39#key-0\"},\"issuer\":\"did:web:api.collab.mosip.net:identity-service:56de166e-0e2f-4734-b8e7-be42b3117d39\",\"@context\":[\"https://www.w3.org/2018/credentials/v1\",\"https://holashchand.github.io/test_project/insurance-context.json\",\"https://w3id.org/security/suites/ed25519-2020/v1\"],\"issuanceDate\":\"2025-05-12T10:51:02.820Z\",\"expirationDate\":\"2025-06-11T10:51:02.814Z\",\"credentialSubject\":{\"id\":\"did:jwk:eyJrdHkiOiJSU0EiLCJlIjoiQVFBQiIsInVzZSI6InNpZyIsImtpZCI6Ii1zUVpsbDhYQXBySGVlNG5CdzB5TUwtLTdsOFJBNGhaM2dMclkzMzdtVUUiLCJhbGciOiJSUzI1NiIsIm4iOiJrUHllWHdIMVM3cjE3WmhOMkl3YmhZejR6bnNEVnl3bDdLRzllUjZ3bUM1YUtaZ0dyY18yWXB1V28tT2RuWDhOc3VWLWFzU0NjU01FVThVdUZqNWtienhRRGdPWFNQWlI1MHVCS19TVEtXTHNVenVlRHpQZUpGdDhibWItVjgtQ0FOa2JrSGRYbXVSS0pUU0JVd3lWRXdtTERnb0ZLYTlVLXhjVTVELWFDcHJFVS1fQ1oyUGZDcF9jdmtJNmdOS2FKRHJBcVVlUkVQYzAzbl93WXd0bE82S1RhQ25jc0JMbEp2U1NBM1B1ZEN5ZFFMVUZwak12R2d3VUlFNkg3d3FoTGdZeXZLTVBTYzVEMG8ybWZ0cHNTVFNrY3p2OEVPdnMtNU5kaHZXTXFlc0dtSE5helk5bDhOMFQyWGxrM0ZqM1lDcXNmQ1lnLUd1RkFRaXpZOU1ZV3cifQ\",\"dob\":\"2025-01-01\",\"email\":\"abcd@gmail.com\",\"gender\":\"Male\",\"mobile\":\"0123456789\",\"benefits\":[\"Critical Surgery\",\"Full body checkup\"],\"fullName\":\"wallet\",\"policyName\":\"wallet\",\"policyNumber\":\"5555\",\"policyIssuedOn\":\"2023-04-20\",\"policyExpiresOn\":\"2033-04-20\"}}"
    )
val ldpCredential2 =
    convertJsonToMap(
        "{\"id\":\"did:rcw:da2d0059-cce8-4bad-923a-217cd381dbd2\",\"type\":[\"VerifiableCredential\",\"InsuranceCredential\"],\"proof\":{\"type\":\"Ed25519Signature2020\",\"created\":\"2025-05-12T10:51:44Z\",\"proofValue\":\"z3rACCjPw79KfPSYGasCVpqyWUpUhEYzPcmo2QLoVtj6LYUxpXi22UBcQdNSFbd3YedVrysS5Svzgcy1uYJEiVPKA\",\"proofPurpose\":\"assertionMethod\",\"verificationMethod\":\"did:web:api.collab.mosip.net:identity-service:56de166e-0e2f-4734-b8e7-be42b3117d39#key-0\"},\"issuer\":\"did:web:api.collab.mosip.net:identity-service:56de166e-0e2f-4734-b8e7-be42b3117d39\",\"@context\":[\"https://www.w3.org/2018/credentials/v1\",\"https://holashchand.github.io/test_project/insurance-context.json\",\"https://w3id.org/security/suites/ed25519-2020/v1\"],\"issuanceDate\":\"2025-05-12T10:51:44.739Z\",\"expirationDate\":\"2025-06-11T10:51:44.734Z\",\"credentialSubject\":{\"id\":\"did:jwk:eyJrdHkiOiJSU0EiLCJlIjoiQVFBQiIsInVzZSI6InNpZyIsImtpZCI6Ii1zUVpsbDhYQXBySGVlNG5CdzB5TUwtLTdsOFJBNGhaM2dMclkzMzdtVUUiLCJhbGciOiJSUzI1NiIsIm4iOiJrUHllWHdIMVM3cjE3WmhOMkl3YmhZejR6bnNEVnl3bDdLRzllUjZ3bUM1YUtaZ0dyY18yWXB1V28tT2RuWDhOc3VWLWFzU0NjU01FVThVdUZqNWtienhRRGdPWFNQWlI1MHVCS19TVEtXTHNVenVlRHpQZUpGdDhibWItVjgtQ0FOa2JrSGRYbXVSS0pUU0JVd3lWRXdtTERnb0ZLYTlVLXhjVTVELWFDcHJFVS1fQ1oyUGZDcF9jdmtJNmdOS2FKRHJBcVVlUkVQYzAzbl93WXd0bE82S1RhQ25jc0JMbEp2U1NBM1B1ZEN5ZFFMVUZwak12R2d3VUlFNkg3d3FoTGdZeXZLTVBTYzVEMG8ybWZ0cHNTVFNrY3p2OEVPdnMtNU5kaHZXTXFlc0dtSE5helk5bDhOMFQyWGxrM0ZqM1lDcXNmQ1lnLUd1RkFRaXpZOU1ZV3cifQ\",\"dob\":\"2025-01-01\",\"email\":\"abcd@gmail.com\",\"gender\":\"Male\",\"mobile\":\"0123456789\",\"benefits\":[\"Critical Surgery\",\"Full body checkup\"],\"fullName\":\"wallet\",\"policyName\":\"wallet\",\"policyNumber\":\"5555\",\"policyIssuedOn\":\"2023-04-20\",\"policyExpiresOn\":\"2033-04-20\"}}"
    )

const val sdJwtCredential1 =
    "eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFZERTQSIsImtpZCI6IiN6Nk1rdHF0WE5HOENEVVk5UHJydG9TdEZ6ZUNuaHBNbWd4WUwxZ2lrY1czQnp2TlcifQ.eyJ2Y3QiOiJJZGVudGl0eUNyZWRlbnRpYWwiLCJmYW1pbHlfbmFtZSI6IkRvZSIsInBob25lX251bWJlciI6IisxLTIwMi01NTUtMDEwMSIsImFkZHJlc3MiOnsic3RyZWV0X2FkZHJlc3MiOiIxMjMgTWFpbiBTdCIsImxvY2FsaXR5IjoiQW55dG93biIsIl9zZCI6WyJOSm5tY3QwQnFCTUUxSmZCbEM2alJRVlJ1ZXZwRU9OaVl3N0E3TUh1SnlRIiwib201Wnp0WkhCLUdkMDBMRzIxQ1ZfeE00RmFFTlNvaWFPWG5UQUpOY3pCNCJdfSwiY25mIjp7Imp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6Im9FTlZzeE9VaUg1NFg4d0pMYVZraWNDUmswMHdCSVE0c1JnYms1NE44TW8ifX0sImlzcyI6ImRpZDprZXk6ejZNa3RxdFhORzhDRFVZOVBycnRvU3RGemVDbmhwTW1neFlMMWdpa2NXM0J6dk5XIiwiaWF0IjoxNjk4MTUxNTMyLCJfc2QiOlsiMUN1cjJrMkEyb0lCNUNzaFNJZl9BX0tnLWwyNnVfcUt1V1E3OVAwVmRhcyIsIlIxelRVdk9ZSGdjZXBqMGpIeXBHSHo5RUh0dFZLZnQweXN3YmM5RVRQYlUiLCJlRHFRcGRUWEpYYldoZi1Fc0k3enc1WDZPdlltRk4tVVpRUU1lc1h3S1B3IiwicGREazJfWEFLSG83Z09BZndGMWI3T2RDVVZUaXQya0pIYXhTRUNROXhmYyIsInBzYXVLVU5XRWkwOW51M0NsODl4S1hnbXBXRU5abDV1eTFOMW55bl9qTWsiLCJzTl9nZTBwSFhGNnFtc1luWDFBOVNkd0o4Y2g4YUVOa3hiT0RzVDc0WXdJIl0sIl9zZF9hbGciOiJzaGEtMjU2In0.Kkhrxy2acd52JTl4g_0x25D5d1QNCTbqHrD9Qu9HzXMxPMu_5T4z-cSiutDYb5cIdi9NzMXPe4MXax-fUymEDg~WyJzYWx0IiwicmVnaW9uIiwiQW55c3RhdGUiXQ~WyJzYWx0IiwiY291bnRyeSIsIlVTIl0~WyJzYWx0IiwiZ2l2ZW5fbmFtZSIsIkpvaG4iXQ~WyJzYWx0IiwiZW1haWwiLCJqb2huZG9lQGV4YW1wbGUuY29tIl0~WyJzYWx0IiwiYmlydGhkYXRlIiwiMTk0MC0wMS0wMSJd~WyJzYWx0IiwiaXNfb3Zlcl8xOCIsdHJ1ZV0~WyJzYWx0IiwiY291bnRyeV8yMSIsdHJ1ZV0~WyJzYWx0IiwiY291bnRyeV82NSIsdHJ1ZV0~"

const val sdJwtCredential2 =
    "eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlCNVRDQ0FZdWdBd0lCQWdJUUdVZEYwa0JpUUdEYXdwKzBkQlNTNWpBS0JnZ3Foa2pPUFFRREFqQWRNUTR3REFZRFZRUURFd1ZCYm1sdGJ6RUxNQWtHQTFVRUJoTUNUa3d3SGhjTk1qVXdOREV5TVRReU16TXdXaGNOTWpZd05UQXlNVFF5TXpNd1dqQWhNUkl3RUFZRFZRUURFd2xqY21Wa2J5QmtZM014Q3pBSkJnTlZCQVlUQWs1TU1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRUZYVk5BMGxhYSs1UDJuazVQSkZvdjh4aEJGTno1VU9KQklWc3lrMFNLU2ZxVGZLTUI2UitjRkROaWpkbUJZeXVFYVVnTWd1VWM4aE9Wbm5yZVc5dGhLT0JxRENCcFRBZEJnTlZIUTRFRmdRVVlSOHZGUVRsa2pmMS9ObktlWnh2WTBaejNhQXdEZ1lEVlIwUEFRSC9CQVFEQWdlQU1CVUdBMVVkSlFFQi93UUxNQWtHQnlpQmpGMEZBUUl3SHdZRFZSMGpCQmd3Rm9BVUw5OHdhTll2OVFueElIYjVDRmd4anZaVXRVc3dJUVlEVlIwU0JCb3dHSVlXYUhSMGNITTZMeTltZFc1clpTNWhibWx0Ynk1cFpEQVpCZ05WSFJFRUVqQVFnZzVtZFc1clpTNWhibWx0Ynk1cFpEQUtCZ2dxaGtqT1BRUURBZ05JQURCRkFpQkJ3ZFMvY0ZCczNhd3RmUDlHRlZrZ1NPSVRRZFBCTUxoc0pCeWpnN2wyTFFJaEFQUUpXeTdxUXNmcTJHcmRwY0dYSHJEVkswdy9YblBGMlhBVDZyVFg4dUNQIiwiTUlJQnp6Q0NBWFdnQXdJQkFnSVFWd0FGb2xXUWltOTRnbXlDaWMzYkNUQUtCZ2dxaGtqT1BRUURBakFkTVE0d0RBWURWUVFERXdWQmJtbHRiekVMTUFrR0ExVUVCaE1DVGt3d0hoY05NalF3TlRBeU1UUXlNek13V2hjTk1qZ3dOVEF5TVRReU16TXdXakFkTVE0d0RBWURWUVFERXdWQmJtbHRiekVMTUFrR0ExVUVCaE1DVGt3d1dUQVRCZ2NxaGtqT1BRSUJCZ2dxaGtqT1BRTUJCd05DQUFRQy9ZeUJwY1JRWDhaWHBIZnJhMVROZFNiUzdxemdIWUhKM21zYklyOFRKTFBOWkk4VWw4ekpsRmRRVklWbHM1KzVDbENiTitKOUZVdmhQR3M0QXpBK280R1dNSUdUTUIwR0ExVWREZ1FXQkJRdjN6Qm8xaS8xQ2ZFZ2R2a0lXREdPOWxTMVN6QU9CZ05WSFE4QkFmOEVCQU1DQVFZd0lRWURWUjBTQkJvd0dJWVdhSFIwY0hNNkx5OW1kVzVyWlM1aGJtbHRieTVwWkRBU0JnTlZIUk1CQWY4RUNEQUdBUUgvQWdFQU1Dc0dBMVVkSHdRa01DSXdJS0Flb0J5R0dtaDBkSEJ6T2k4dlpuVnVhMlV1WVc1cGJXOHVhV1F2WTNKc01Bb0dDQ3FHU000OUJBTUNBMGdBTUVVQ0lRQ1RnODBBbXFWSEpMYVp0MnV1aEF0UHFLSVhhZlAyZ2h0ZDlPQ21kRDUxWndJZ0t2VmtyZ1RZbHhTUkFibUtZNk1sa0g4bU0zU05jbkVKazlmR1Z3SkcrKzA9Il19.ewogICJpc3N1YW5jZV9kYXRlIjogIjIwMjUtMDgtMTgiLAogICJleHBpcnlfZGF0ZSI6ICIyMDI2LTA4LTI4IiwKICAiaXNzdWluZ19jb3VudHJ5IjogIkRFIiwKICAibmJmIjogMTc1NTQ3NTIwMCwKICAiZXhwIjogMTc4Nzg3NTIwMCwKICAidmN0IjogImh0dHBzOi8vZXhhbXBsZS5ldWRpLmVjLmV1cm9wYS5ldS9jb3IvMSIsCiAgImlzcyI6ICJodHRwczovL2Z1bmtlLmFuaW1vLmlkIiwKICAiaWF0IjogMTc1Njg5NjY1MywKICAiX3NkIjogWwogICAgIkMyUF9xb3EwUHZUbzFZWXJ2M181RldpNGlFYVpVR0tZYUNremFrZ01JSGMiLAogICAgIkY0WmRCUEl4MHJRYmhuaWRuU3AxSEw3LVRSX09DRnFoV0lWSlo3bUIzRlUiLAogICAgIlV0di10R2hJZ29LSUtOVGI5Z3RicjdiWTlFbVFBTUtOd3RYamNNc1FwTE0iLAogICAgImd3X0ZqLTRMUUZKQ2dyZFVKcEVCbW00bnphMzFYUnRhZzVTaF9FUDhEelUiLAogICAgImthdDRVQW1LOXhuTkd6NS14RXZDVHVmZW5BRzlSdUVveHlrckstbE5LZWciLAogICAgIm9FQkxLVzRRRDlnY0puSEJGLVhHZWtsQTN4OEwxNXVsQ3c1VXFwZXloSXMiLAogICAgInF0aVVKemxTTDlNMm43eXhnaGtJTkp4VUp0NktmWmRQY0RrcWh0VnE0elEiLAogICAgInk0THlyMno2QUlkSGhwOGV0NVZxOXJoU2I2NXNHaU1YMDZFVloxLV9pNlEiCiAgXSwKICAiX3NkX2FsZyI6ICJzaGEtMjU2Igp9.F0gYaWKFzPXoI4pO4mixg6WgN1gM3hfqiJLIgxEAjfQb5yrQEU3G2CCYwJtg7d9bcs9-4lu4ZVS6aWpUJ70UNw~WyI1Njg2Njc5MzY5MTc4MDgxMDA5Nzc0MTQiLCJmYW1pbHlfbmFtZSIsIk11c3Rlcm1hbm4iXQ~WyIxMTc2MjI4NDI0Mzk4MTY4Mzc4NTQ1NTg0IiwiZ2l2ZW5fbmFtZSIsIkVyaWthIl0~WyI1MTI2Mzc4NDkyMDcxOTExMjczMTQwNjAiLCJiaXJ0aF9kYXRlIiwiMTk2NC0wOC0xMiJd~WyIxMTI0MjE5NzQ2NzM0MDA1ODYzMjU3NTAiLCJyZXNpZGVudF9hZGRyZXNzIiwiSGVpZGVzdHJhc3NlIDE3LCA1MTE0NyBLb2xuIl0~WyI1MzcxMzg4MzMyNjMxMDc3MjY5MjQ4NDkiLCJnZW5kZXIiLDJd~WyI5MjcxODEyMjgxOTIyMDY1MDcxOTQyMTMiLCJiaXJ0aF9wbGFjZSIsIkvDtmxuIl0~WyI1MTE2NDk3MzQxMDM5NTU1MTIwMzc0MDQiLCJhcnJpdmFsX2RhdGUiLCIyMDI0LTAzLTAxIl0~WyI5MTQ0NDg4OTMwNzAwNzQ5Mjc3NjMwODkiLCJuYXRpb25hbGl0eSIsIkRFIl0~"

const val clientId = "client-id"
const val verifierNonce = "GM12ZywLxmA0PjQFevb/WQ=="
const val walletNonce = "P0RVGUe5OoDctvuK"

const val publicKey = """-----BEGIN RSA PUBLIC KEY-----publickey-----END RSA PUBLIC KEY-----"""
const val signatureSuite = "JsonWebSignature2020"

const val jws =
    "eyJhbGciOiJFZERTQSIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6ImtldWxwNGVVU0d1eEVLSDlzQ0JkaTN1ek1sQmQ4cE1wMVdlamhTUFZybUEiLCJhbGciOiJFZDI1NTE5IiwidXNlIjoic2lnIn19..NGhwSDJoTktZT25kU2lVc3JwUEJoY1dld2JjT1FxQ2RsQW9qNFlENktMam9WT0M0N1RDMXk5cXFGTWpwZUVsMFhHeWNFZmpEd0s0N2pKOXFZOHFKRGc"

val unsignedLdpVPToken: List<UnsignedVPToken> = listOf(
    UnsignedVPToken(
        id = RANDOM_UUID,
        format = FormatType.LDP_VC,
        holderKeyReference = "did:example:holder",
        signatureAlgorithm = signatureSuite,
        dataToSign = "base64EncodedCanonicalisedData".toByteArray()
    )
)
@OptIn(ExperimentalStdlibApi::class)
val mdocDocTypeToDeviceAuthBytes: Map<String, ByteArray> = mapOf(
    "mdoc-uuid1" to "d8185892847444657669636541757468656e7469636174696f6e83f6f6835820ed084cf67d819fdc2ab6711e1a36053719358b46bfbf51a523c690f9cb6b1e5d5820ed084cf67d819fdc2ab6711e1a36053719358b46bfbf51a523c690f9cb6b1e5d7818624d487658314847686268387a716c5357662f6675513d3d756f72672e69736f2e31383031332e352e312e6d444cd81841a0".hexToByteArray()
)
val unsignedMdocVPToken: List<UnsignedVPToken> = listOf(
    UnsignedVPToken(
        id = RANDOM_UUID,
        format = FormatType.MSO_MDOC,
        holderKeyReference = "mdocKeyRef",
        signatureAlgorithm = "ES256",
        dataToSign = "d8185892847444657669636541757468656e7469636174696f6e83f6f6835820ed084cf67d819fdc2ab6711e1a36053719358b46bfbf51a523c690f9cb6b1e5d5820ed084cf67d819fdc2ab6711e1a36053719358b46bfbf51a523c690f9cb6b1e5d7818624d487658314847686268387a716c5357662f6675513d3d756f72672e69736f2e31383031332e352e312e6d444cd81841a0".toByteArray()
    )
)
val unsignedSdJwtVPToken: List<UnsignedVPToken> = listOf(
    UnsignedVPToken(
        id = RANDOM_UUID,
        format = FormatType.VC_SD_JWT,
        holderKeyReference = "kid123",
        signatureAlgorithm = "ES256K",
        dataToSign = "unsignedKBT1".toByteArray()
    ),
    UnsignedVPToken(
        id = RANDOM_UUID,
        format = FormatType.VC_SD_JWT,
        holderKeyReference = "kid456",
        signatureAlgorithm = "ES256K",
        dataToSign = "unsignedKBT2".toByteArray()
    )
)
val sdJwtIdToUnsignedKBJWT: Map<String, String> = mapOf(
    "123" to "unsignedKBT1",
    "sd-jwt-uuid1" to "unsignedKBT1",
    "456" to "unsignedKBT2",
    "sd-jwt-uuid2" to "unsignedKBT2"
)

val clientMetadataMap = mapOf(
    "client_name" to "Requester name",
    "logo_uri" to "<logo_uri>",
    "authorization_encrypted_response_alg" to "ECDH-ES",
    "authorization_encrypted_response_enc" to "A256GCM",
    "vp_formats" to mapOf(
        "ldp_vc" to mapOf(
            "proof_type" to listOf(
                "Ed25519Signature2018",
                "Ed25519Signature2020"
            )
        )
    )
)

private val vpFormatsMap = mapOf(
    VPFormatType.LDP_VC to LdpVpFormatSupported(
        proofTypeValues = listOf(ProofType.Ed25519Signature2020)
    ) as VPFormatSupported
)

val walletConfig = WalletConfig(
    vpFormatsSupported = vpFormatsMap,
    clientIdPrefixesSupported = listOf(
        ClientIdPrefix.REDIRECT_URI,
        ClientIdPrefix.DECENTRALIZED_IDENTIFIER,
        ClientIdPrefix.PRE_REGISTERED
    ),
    requestObjectSigningAlgValuesSupported = listOf(SignatureAlgorithm.EdDSA),
    authorizationEncryptionAlgValuesSupported = listOf(EncryptionAlgorithm.ECDH_ES),
    authorizationEncryptionEncValuesSupported = listOf(EncryptionMethod.A256GCM),
)

internal val jwkList = listOf(
    Jwk(
        kty = "OKP",
        crv = "Ed25519",
        use = "sig",
        x = "-Fy3lMapzR3wpaYNCFq29GDEn_NoR3pBsc511q1Cxqw",
        alg = "EdDSA",
        kid = "test-key"
    )
)

val clientMetadataString = """{
  "client_name": "Requester name",
  "logo_uri": "<logo_uri>",
  "authorization_encrypted_response_alg": "ECDH-ES",
  "authorization_encrypted_response_enc": "A256GCM",
  "jwks": {
    "keys": [
       {
         "kty": "OKP",
         "d": "kDOXcN7Wo8gr5Uf_r59_7wGo9FJGGRFpIUnbAV-WxjQ",
         "use": "enc",
         "crv": "X25519",
         "kid": "enc-key-with-wrap",
         "x": "-qsgagp8GUre4EPpsfDIyx3ZIlRKt-H6imaxgiX5nRg",
         "alg": "ECDH-ES+A128KW"
       },
      {
        "kty": "OKP",
        "crv": "X25519",
        "use": "enc",
        "x": "BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4",
        "alg": "ECDH-ES",
        "kid": "enc-key1"
      },
      {
        "kty": "OKP",
        "crv": "Ed25519",
        "use": "sig",
        "x": "-Fy3lMapzR3wpaYNCFq29GDEn_NoR3pBsc511q1Cxqw", 
        "alg": "EdDSA",
        "kid": "sig-key1"
      }
    ]
  },
  "vp_formats": {
    "ldp_vc": {
      "proof_type": [
        "Ed25519Signature2018",
        "Ed25519Signature2020"
      ]
    }
  }
}
""".trimIndent()


val presentationDefinitionMap = mapOf(
    "id" to "649d581c-f891-4969-9cd5-2c27385a348f",
    "input_descriptors" to listOf(
        mapOf(
            "id" to "idcardcredential",
            "format" to mapOf(
                "ldp_vc" to mapOf(
                    "proof_type" to listOf("Ed25519Signature2018")
                )
            ),
            "constraints" to mapOf(
                "fields" to listOf(
                    mapOf(
                        "path" to listOf(TYPE_PATH)
                    )
                )
            )
        )
    )
)

val presentationDefinitionMapWithSdJwt = mapOf(
    "id" to "vp token example",
    "purpose" to "Relying party is requesting your digital ID for the purpose of Self-Authentication",
    "input_descriptors" to listOf(
        mapOf(
            "id" to "id_card_ldp_vc",
            "format" to mapOf(
                "ldp_vc" to mapOf(
                    "proof_type" to listOf("Ed25519Signature2020", "RsaSignature2018")
                )
            ),
            "constraints" to mapOf(
                "fields" to listOf(
                    mapOf(
                        "path" to listOf(TYPE_PATH),
                    )
                )
            )
        ),
        mapOf(
            "id" to "id_card_sd_jwt",
            "format" to mapOf(
                "vc+sd-jwt" to {}
            ),
            "constraints" to mapOf(
                "fields" to listOf(
                    mapOf(
                        "path" to listOf(TYPE_PATH),
                        "filter" to mapOf(
                            "type" to "string",
                            "pattern" to ".*"
                        )
                    )
                )
            )
        ),
        mapOf(
            "id" to "id_card_mso_mdoc",
            "format" to mapOf(
                "mso_mdoc" to mapOf(
                    "alg" to listOf("ES256")
                )
            ),
            "constraints" to mapOf(
                "fields" to listOf(
                    mapOf(
                        "path" to listOf(TYPE_PATH),
                        "filter" to mapOf(
                            "type" to "string",
                            "pattern" to ".*"
                        )
                    )
                )
            )
        )
    )
)


val presentationDefinitionString = """
    {
      "id": "649d581c-f891-4969-9cd5-2c27385a348f",
      "input_descriptors": [
        {
          "id": "idcardcredential",
          "format": {
            "ldp_vc": {
              "proof_type": [
                "Ed25519Signature2018"
              ]
            }
          },
          "constraints": {
            "fields": [
              {
                "path": [
                  "$TYPE_PATH"
                ]
              }
            ]
          }
        }
      ]
    }
""".trimIndent()

val didResponse = """
    {
        "assertionMethod": [
          "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs#key-0"
        ],
        "service": [],
        "id": "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs",
        "verificationMethod": [
          {
            "publicKeyMultibase": "z6MkwAm9tLpXZNfeEAqj9jcccFhjdiTwxVD32GhcjyeqGYSo",
            "controller": "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs",
            "id": "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs#key-0",
            "type": "Ed25519VerificationKey2020",
            "@context": "https://w3id.org/security/suites/ed25519-2020/v1"
          }
        ],
        "@context": [
          "https://www.w3.org/ns/did/v1"
        ],
        "alsoKnownAs": [],
        "authentication": [
          "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs#key-0"
        ]
      }
""".trimIndent()


internal val didPublicKey : PublicKey = toJavaPublicKey("z6MkwAm9tLpXZNfeEAqj9jcccFhjdiTwxVD32GhcjyeqGYSo", "Ed25519")

val trustedVerifiers: List<Verifier> = listOf(
    Verifier(
        "mock-client", listOf(
            "https://mock-verifier.com/response-uri", "https://verifier.env2.com/responseUri"
        ),
        "https://mock-verifier.com/.well-known/jwks.json",
        true,
        SpecVersion.DRAFT_23
    ), Verifier(
        "mock-client2", listOf(
            "https://verifier.env3.com/responseUri", "https://verifier.env2.com/responseUri"
        )
    )
)

val authRequestParamsByReferenceDraft23 = listOf(
    CLIENT_ID.value,
    REQUEST_URI.value,
    REQUEST_URI_METHOD.value
)

val authRequestParamsByReferenceDraft21 = listOf(
    CLIENT_ID.value,
    "client_id_scheme",
    REQUEST_URI.value,
    REQUEST_URI_METHOD.value
)

val authRequestWithRedirectUriByValue = listOf(
    CLIENT_ID.value,
    RESPONSE_URI.value,
    RESPONSE_MODE.value,
    PRESENTATION_DEFINITION.value,
    RESPONSE_TYPE.value,
    NONCE.value,
    STATE.value,
    CLIENT_METADATA.value
)

val authRequestWithPreRegisteredByValue = listOf(
    CLIENT_ID.value,
    RESPONSE_MODE.value,
    RESPONSE_URI.value,
    PRESENTATION_DEFINITION.value,
    RESPONSE_TYPE.value,
    NONCE.value,
    STATE.value
)

val authRequestWithDidByValue = listOf(
    CLIENT_ID.value,
    RESPONSE_MODE.value,
    RESPONSE_URI.value,
    PRESENTATION_DEFINITION.value,
    RESPONSE_TYPE.value,
    NONCE.value,
    STATE.value,
    CLIENT_METADATA.value
)

val requestParams: MutableMap<String, String> = mapOf(
    REDIRECT_URI.value to MOCK_VERIFIER,
    RESPONSE_URI.value to responseUrl,
    REQUEST_URI.value to requestUrl,
    REQUEST_URI_METHOD.value to "get",
    PRESENTATION_DEFINITION.value to presentationDefinitionString,
    PRESENTATION_DEFINITION_URI.value to "https://mock-verifier.com/verifier/get-presentation-definition",
    RESPONSE_TYPE.value to "vp_token",
    RESPONSE_MODE.value to "direct_post",
    NONCE.value to TEST_KEY_1,
    STATE.value to "+mRQe1d6pBoJqF6Ab28klg==",
    CLIENT_METADATA.value to clientMetadataString
).toMutableMap()

val authorisationRequestListToClientIdSchemeMap = mapOf(
    ClientIdPrefix.DECENTRALIZED_IDENTIFIER to authRequestWithDidByValue,
    ClientIdPrefix.REDIRECT_URI to authRequestWithRedirectUriByValue,
    ClientIdPrefix.PRE_REGISTERED to authRequestWithPreRegisteredByValue
)

val clientIdOfDid = mapOf(
    CLIENT_ID.value to didUrl,
)

val clientIdOfPreRegistered = mapOf(
    CLIENT_ID.value to "mock-client",
)

val clientIdOfReDirectUriDraft23 = mapOf(
    CLIENT_ID.value to "${REDIRECT_URI.value}:https://mock-verifier.com/response-uri",
)

val clientMetadataPresentationDefinitionMap = mapOf(
    PRESENTATION_DEFINITION.value to presentationDefinitionMap,
    CLIENT_METADATA.value to clientMetadataMap
)


val authorizationRequestForResponseModeJWT = AuthorizationPresentationExchangeRequest(
    clientId = "https://injiverify.dev2.mosip.net",
    responseType = "vp_token",
    responseMode = "direct_post.jwt",
    presentationDefinition = deserializeAndValidate(
        presentationDefinitionString,
        PresentationDefinitionSerializer
    ),
    responseUri = responseUrl,
    redirectUri = null,
    nonce = TEST_KEY_2,
    state = "fsnC8ixCs6mWyV+00k23Qg==",
    clientMetadata = deserializeAndValidate(clientMetadataString, ClientMetadataDraft23Serializer),
    walletNonce = TEST_KEY_1
)

val authorizationPresentationExchangeRequest = AuthorizationPresentationExchangeRequest(
    clientId = MOCK_VERIFIER,
    responseType = "vp_token",
    responseMode = "direct_post",
    presentationDefinition = deserializeAndValidate(
        presentationDefinitionMap,
        PresentationDefinitionSerializer
    ),
    responseUri = MOCK_VERIFIER,
    redirectUri = null,
    nonce = TEST_KEY_2,
    state = "fsnC8ixCs6mWyV+00k23Qg==",
    clientMetadata = deserializeAndValidate(clientMetadataMap, ClientMetadataDraft23Serializer),
    walletNonce = TEST_KEY_1
)

fun createAuthorizationRequestWithState(state: String?): AuthorizationPresentationExchangeRequest {
    return AuthorizationPresentationExchangeRequest(
        clientId = authorizationPresentationExchangeRequest.clientId,
        responseType = authorizationPresentationExchangeRequest.responseType,
        responseMode = authorizationPresentationExchangeRequest.responseMode,
        presentationDefinition = authorizationPresentationExchangeRequest.presentationDefinition,
        responseUri = authorizationPresentationExchangeRequest.responseUri,
        redirectUri = authorizationPresentationExchangeRequest.redirectUri,
        nonce = authorizationPresentationExchangeRequest.nonce,
        state = state,
        clientMetadata = authorizationPresentationExchangeRequest.clientMetadata,
        walletNonce = authorizationPresentationExchangeRequest.walletNonce
    )
}

val proof = Proof(
    type = "RsaSignature2018",
    created = "2024-02-13T10:00:00Z",
    challenge = TEST_KEY_2,
    domain = "https://123",
    proofValue = jws,
    proofPurpose = "authentication",
    verificationMethod = publicKey
)

val ldpVPToken = LdpVPToken(
    context = listOf("context"),
    type = listOf("type"),
    verifiableCredential = listOf(ldpCredential1, ldpCredential2, ldpCredential2),
    id = "id",
    holder = "holder",
    proof = proof
)

val ldpVPToken2 = LdpVPToken(
    context = listOf("context"),
    type = listOf("type"),
    verifiableCredential = listOf(ldpCredential1, ldpCredential2),
    id = "id",
    holder = "holder",
    proof = proof
)

val vpTokenSigningPayload = mapOf("ldp-uuid1" to LdpVPToken(
    context = listOf("context"),
    type = listOf("type"),
    verifiableCredential = listOf(ldpCredential1, ldpCredential2,ldpCredential2),
    id = "id",
    holder = "holder",
    proof = proof.apply {
        jws = null
        proofValue = null
    }
))

val vpTokenSigningPayload2 = LdpVPToken(
    context = listOf("context"),
    type = listOf("type"),
    verifiableCredential = listOf(ldpCredential1, ldpCredential2),
    id = "id",
    holder = "holder",
    proof = proof.apply {
        jws = null
        proofValue = null
    }
)

val mdocVPToken = MdocVPToken(
    base64EncodedDeviceResponse = "base64EncodedDeviceResponse",
)
val vpToken = VPTokenType.VPTokenElement(
    ldpVPToken
)

val presentationSubmission = PresentationSubmission(
    id = "ps_id",
    definitionId = "client_id",
    descriptorMap = listOf(
        DescriptorMap(
            id = "input_descriptor_1",
            format = "ldp_vp",
            path = "$",
            pathNested = PathNested(
                id = "input_descriptor_1",
                format = "ldp_vp",
                path = "$.verifiableCredential[0]"
            )
        )
    )
)
val authorizationResponse = AuthorizationResponse.PresentationExchange(
    presentationSubmission = presentationSubmission,
    vpToken = vpToken,
    state = "state"
)

internal const val sampleVcSdJwtWithNoHolderBinding = "eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlCNVRDQ0FZdWdBd0lCQWdJUUdVZEYwa0JpUUdEYXdwKzBkQlNTNWpBS0JnZ3Foa2pPUFFRREFqQWRNUTR3REFZRFZRUURFd1ZCYm1sdGJ6RUxNQWtHQTFVRUJoTUNUa3d3SGhjTk1qVXdOREV5TVRReU16TXdXaGNOTWpZd05UQXlNVFF5TXpNd1dqQWhNUkl3RUFZRFZRUURFd2xqY21Wa2J5QmtZM014Q3pBSkJnTlZCQVlUQWs1TU1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRUZYVk5BMGxhYSs1UDJuazVQSkZvdjh4aEJGTno1VU9KQklWc3lrMFNLU2ZxVGZLTUI2UitjRkROaWpkbUJZeXVFYVVnTWd1VWM4aE9Wbm5yZVc5dGhLT0JxRENCcFRBZEJnTlZIUTRFRmdRVVlSOHZGUVRsa2pmMS9ObktlWnh2WTBaejNhQXdEZ1lEVlIwUEFRSC9CQVFEQWdlQU1CVUdBMVVkSlFFQi93UUxNQWtHQnlpQmpGMEZBUUl3SHdZRFZSMGpCQmd3Rm9BVUw5OHdhTll2OVFueElIYjVDRmd4anZaVXRVc3dJUVlEVlIwU0JCb3dHSVlXYUhSMGNITTZMeTltZFc1clpTNWhibWx0Ynk1cFpEQVpCZ05WSFJFRUVqQVFnZzVtZFc1clpTNWhibWx0Ynk1cFpEQUtCZ2dxaGtqT1BRUURBZ05JQURCRkFpQkJ3ZFMvY0ZCczNhd3RmUDlHRlZrZ1NPSVRRZFBCTUxoc0pCeWpnN2wyTFFJaEFQUUpXeTdxUXNmcTJHcmRwY0dYSHJEVkswdy9YblBGMlhBVDZyVFg4dUNQIiwiTUlJQnp6Q0NBWFdnQXdJQkFnSVFWd0FGb2xXUWltOTRnbXlDaWMzYkNUQUtCZ2dxaGtqT1BRUURBakFkTVE0d0RBWURWUVFERXdWQmJtbHRiekVMTUFrR0ExVUVCaE1DVGt3d0hoY05NalF3TlRBeU1UUXlNek13V2hjTk1qZ3dOVEF5TVRReU16TXdXakFkTVE0d0RBWURWUVFERXdWQmJtbHRiekVMTUFrR0ExVUVCaE1DVGt3d1dUQVRCZ2NxaGtqT1BRSUJCZ2dxaGtqT1BRTUJCd05DQUFRQy9ZeUJwY1JRWDhaWHBIZnJhMVROZFNiUzdxemdIWUhKM21zYklyOFRKTFBOWkk4VWw4ekpsRmRRVklWbHM1KzVDbENiTitKOUZVdmhQR3M0QXpBK280R1dNSUdUTUIwR0ExVWREZ1FXQkJRdjN6Qm8xaS8xQ2ZFZ2R2a0lXREdPOWxTMVN6QU9CZ05WSFE4QkFmOEVCQU1DQVFZd0lRWURWUjBTQkJvd0dJWVdhSFIwY0hNNkx5OW1kVzVyWlM1aGJtbHRieTVwWkRBU0JnTlZIUk1CQWY4RUNEQUdBUUgvQWdFQU1Dc0dBMVVkSHdRa01DSXdJS0Flb0J5R0dtaDBkSEJ6T2k4dlpuVnVhMlV1WVc1cGJXOHVhV1F2WTNKc01Bb0dDQ3FHU000OUJBTUNBMGdBTUVVQ0lRQ1RnODBBbXFWSEpMYVp0MnV1aEF0UHFLSVhhZlAyZ2h0ZDlPQ21kRDUxWndJZ0t2VmtyZ1RZbHhTUkFibUtZNk1sa0g4bU0zU05jbkVKazlmR1Z3SkcrKzA9Il19.ewogICJpc3N1YW5jZV9kYXRlIjogIjIwMjUtMDgtMTgiLAogICJleHBpcnlfZGF0ZSI6ICIyMDI2LTA4LTI4IiwKICAiaXNzdWluZ19jb3VudHJ5IjogIkRFIiwKICAibmJmIjogMTc1NTQ3NTIwMCwKICAiZXhwIjogMTc4Nzg3NTIwMCwKICAidmN0IjogImh0dHBzOi8vZXhhbXBsZS5ldWRpLmVjLmV1cm9wYS5ldS9jb3IvMSIsCiAgImlzcyI6ICJodHRwczovL2Z1bmtlLmFuaW1vLmlkIiwKICAiaWF0IjogMTc1Njg5NjY1MywKICAiX3NkIjogWwogICAgIkMyUF9xb3EwUHZUbzFZWXJ2M181RldpNGlFYVpVR0tZYUNremFrZ01JSGMiLAogICAgIkY0WmRCUEl4MHJRYmhuaWRuU3AxSEw3LVRSX09DRnFoV0lWSlo3bUIzRlUiLAogICAgIlV0di10R2hJZ29LSUtOVGI5Z3RicjdiWTlFbVFBTUtOd3RYamNNc1FwTE0iLAogICAgImd3X0ZqLTRMUUZKQ2dyZFVKcEVCbW00bnphMzFYUnRhZzVTaF9FUDhEelUiLAogICAgImthdDRVQW1LOXhuTkd6NS14RXZDVHVmZW5BRzlSdUVveHlrckstbE5LZWciLAogICAgIm9FQkxLVzRRRDlnY0puSEJGLVhHZWtsQTN4OEwxNXVsQ3c1VXFwZXloSXMiLAogICAgInF0aVVKemxTTDlNMm43eXhnaGtJTkp4VUp0NktmWmRQY0RrcWh0VnE0elEiLAogICAgInk0THlyMno2QUlkSGhwOGV0NVZxOXJoU2I2NXNHaU1YMDZFVloxLV9pNlEiCiAgXSwKICAiX3NkX2FsZyI6ICJzaGEtMjU2Igp9.F0gYaWKFzPXoI4pO4mixg6WgN1gM3hfqiJLIgxEAjfQb5yrQEU3G2CCYwJtg7d9bcs9-4lu4ZVS6aWpUJ70UNw~WyI1Njg2Njc5MzY5MTc4MDgxMDA5Nzc0MTQiLCJmYW1pbHlfbmFtZSIsIk11c3Rlcm1hbm4iXQ~WyIxMTc2MjI4NDI0Mzk4MTY4Mzc4NTQ1NTg0IiwiZ2l2ZW5fbmFtZSIsIkVyaWthIl0~WyI1MTI2Mzc4NDkyMDcxOTExMjczMTQwNjAiLCJiaXJ0aF9kYXRlIiwiMTk2NC0wOC0xMiJd~WyIxMTI0MjE5NzQ2NzM0MDA1ODYzMjU3NTAiLCJyZXNpZGVudF9hZGRyZXNzIiwiSGVpZGVzdHJhc3NlIDE3LCA1MTE0NyBLb2xuIl0~WyI1MzcxMzg4MzMyNjMxMDc3MjY5MjQ4NDkiLCJnZW5kZXIiLDJd~WyI5MjcxODEyMjgxOTIyMDY1MDcxOTQyMTMiLCJiaXJ0aF9wbGFjZSIsIkvDtmxuIl0~WyI1MTE2NDk3MzQxMDM5NTU1MTIwMzc0MDQiLCJhcnJpdmFsX2RhdGUiLCIyMDI0LTAzLTAxIl0~WyI5MTQ0NDg4OTMwNzAwNzQ5Mjc3NjMwODkiLCJuYXRpb25hbGl0eSIsIkRFIl0~"

internal const val sampleMdoc = "omdkb2NUeXBldW9yZy5pc28uMTgwMTMuNS4xLm1ETGxpc3N1ZXJTaWduZWSiam5hbWVTcGFjZXOhcW9yZy5pc28uMTgwMTMuNS4xiNgYWFukaGRpZ2VzdElEAWZyYW5kb21QcbnmTIHt0_17t"
