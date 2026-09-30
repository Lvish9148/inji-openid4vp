package io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler

import io.mosip.openID4VP.common.encodeToBase64Url
import io.mosip.openID4VP.common.decodeFromBase64Url
import io.mockk.*
import io.mosip.openID4VP.OpenID4VP
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.*
import io.mosip.openID4VP.authorizationRequest.WalletConfig
import io.mosip.openID4VP.constants.ClientIdPrefix.PRE_REGISTERED
import io.mosip.openID4VP.constants.ClientIdPrefix.REDIRECT_URI
import io.mosip.openID4VP.constants.HttpMethod
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.networkManager.NetworkManagerClient
import io.mosip.openID4VP.networkManager.NetworkResponse
import io.mosip.openID4VP.testData.*
import kotlin.test.*

private const val AUTHZ_REQ_JWT_TYP = "oauth-authz-req+jwt"
/**
 * Tests for ClientIdPrefixBasedAuthorizationRequestHandler.kt changes from PR #111:
 * - JWS typ header validation (must be "oauth-authz-req+jwt")
 * - client_id_prefix terminology in error messages
 * - SpecVersionHandler dispatch (Draft23 vs V1)
 */
class ClientIdPrefixBasedAuthorizationRequestHandlerTypValidationTest {

    private lateinit var openID4VP: OpenID4VP

    @BeforeTest
    fun setUp() {
        mockkStatic("io.mosip.openID4VP.common.EncoderKt")
        every { encodeToBase64Url(any()) } answers { java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(firstArg()) }
        mockkStatic("io.mosip.openID4VP.common.DecoderKt")
        every { decodeFromBase64Url(any()) } answers { java.util.Base64.getUrlDecoder().decode(firstArg<String>()) }
        mockkObject(NetworkManagerClient)
        openID4VP = OpenID4VP("typ-validation-test", WalletConfig(trustedVerifiers = trustedVerifiers))
    }

    @AfterTest
    fun tearDown() {
        clearAllMocks()
    }

    @Test
    fun `should reject signed request with missing typ header`() {
        val authorizationRequestParamsMap = requestParams + clientIdOfPreRegistered
        val jwtWithNoTyp = createAuthorizationRequestObject(
            clientIdScheme = PRE_REGISTERED,
            authorizationRequestParams = authorizationRequestParamsMap,
            jwtHeader = createJwtHeaderWithoutTyp()
        )
        val encodedRequest = createUrlEncodedData(
            requestParams = authorizationRequestParamsMap + mapOf("request" to jwtWithNoTyp.toString()),
            clientIdScheme = PRE_REGISTERED,
            applicableFields = listOf(CLIENT_ID.value, "request")
        )

        val exception = assertFailsWith<OpenID4VPExceptions> {
            openID4VP.authenticateVerifier(encodedRequest)
        }

        assertTrue(
            exception.message!!.contains("typ") || exception.message!!.contains(AUTHZ_REQ_JWT_TYP),
            "Error should mention typ header validation failure, got: ${exception.message}"
        )
    }

    @Test
    fun `should reject signed request with wrong typ header value`() {
        val authorizationRequestParamsMap = requestParams + clientIdOfPreRegistered
        val jwtWithWrongTyp = createAuthorizationRequestObject(
            clientIdScheme = PRE_REGISTERED,
            authorizationRequestParams = authorizationRequestParamsMap,
            jwtHeader = createJwtHeaderWithTyp("JWT")
        )
        val encodedRequest = createUrlEncodedData(
            requestParams = authorizationRequestParamsMap + mapOf("request" to jwtWithWrongTyp.toString()),
            clientIdScheme = PRE_REGISTERED,
            applicableFields = listOf(CLIENT_ID.value, "request")
        )

        val exception = assertFailsWith<OpenID4VPExceptions> {
            openID4VP.authenticateVerifier(encodedRequest)
        }

        assertTrue(
            exception.message!!.contains(AUTHZ_REQ_JWT_TYP),
            "Error should mention expected typ value, got: ${exception.message}"
        )
    }

    @Test
    fun `should reject request_uri response with invalid typ header`() {
        val authorizationRequestParamsMap = requestParams + clientIdOfPreRegistered

        val jwtWithBadTyp = createAuthorizationRequestObject(
            clientIdScheme = PRE_REGISTERED,
            authorizationRequestParams = authorizationRequestParamsMap,
            jwtHeader = createJwtHeaderWithTyp("at+jwt")
        )

        every {
            NetworkManagerClient.sendHTTPRequest(
                requestUrl, HttpMethod.GET, null, any()
            )
        } returns NetworkResponse(
            200,
            jwtWithBadTyp.toString(),
            mapOf("content-type" to listOf("application/oauth-authz-req+jwt"))
        )

        val encodedRequest = createUrlEncodedData(
            requestParams = authorizationRequestParamsMap,
            verifierSentAuthRequestByReference = true,
            clientIdScheme = PRE_REGISTERED
        )

        val exception = assertFailsWith<OpenID4VPExceptions> {
            openID4VP.authenticateVerifier(encodedRequest)
        }

        assertTrue(
            exception.message!!.contains(AUTHZ_REQ_JWT_TYP) || exception.message!!.contains("typ"),
            "Error should mention typ validation, got: ${exception.message}"
        )
    }

    @Test
    fun `error messages use client_id_prefix terminology not client_id_scheme`() {
        // Test that redirect_uri prefix unsigned request handler uses "client_id_prefix" in messages
        val redirectUriClientId = "redirect_uri:https://mock-verifier.com/response-uri"
        val paramsWithRequestUri = mapOf(
            CLIENT_ID.value to redirectUriClientId,
            REQUEST_URI.value to requestUrl,
            REQUEST_URI_METHOD.value to "get"
        )

        every {
            NetworkManagerClient.sendHTTPRequest(requestUrl, HttpMethod.GET, null, any())
        } returns NetworkResponse(200, "not-a-jwt", mapOf("content-type" to listOf("application/oauth-authz-req+jwt")))

        val encodedRequest = createUrlEncodedData(
            requestParams = paramsWithRequestUri.toMutableMap(),
            verifierSentAuthRequestByReference = true,
            clientIdScheme = REDIRECT_URI
        )

        val exception = assertFailsWith<OpenID4VPExceptions> {
            openID4VP.authenticateVerifier(encodedRequest)
        }

        assertTrue(
            exception.message!!.contains("client_id_prefix"),
            "Error message should use 'client_id_prefix' not 'client_id_scheme', got: ${exception.message}"
        )
    }

    // --- Helpers ---

    private fun createJwtHeaderWithoutTyp(): kotlinx.serialization.json.JsonObject {
        return kotlinx.serialization.json.buildJsonObject {
            put("alg", kotlinx.serialization.json.JsonPrimitive("EdDSA"))
            put("kid", kotlinx.serialization.json.JsonPrimitive("test-key"))
        }
    }

    private fun createJwtHeaderWithTyp(typ: String): kotlinx.serialization.json.JsonObject {
        return kotlinx.serialization.json.buildJsonObject {
            put("alg", kotlinx.serialization.json.JsonPrimitive("EdDSA"))
            put("kid", kotlinx.serialization.json.JsonPrimitive("test-key"))
            put("typ", kotlinx.serialization.json.JsonPrimitive(typ))
        }
    }
}
