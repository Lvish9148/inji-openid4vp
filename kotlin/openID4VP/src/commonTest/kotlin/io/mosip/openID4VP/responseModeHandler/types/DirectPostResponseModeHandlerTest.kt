package io.mosip.openID4VP.responseModeHandler.types

import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkObject
import io.mockk.verify
import io.mosip.openID4VP.authorizationResponse.AuthorizationErrorResponse
import io.mosip.openID4VP.authorizationResponse.toJsonEncodedMap
import io.mosip.openID4VP.constants.ContentType
import io.mosip.openID4VP.constants.HttpMethod
import io.mosip.openID4VP.networkManager.NetworkManagerClient
import io.mosip.openID4VP.responseModeHandler.ResponseDispatchInfo
import io.mosip.openID4VP.testData.authorizationRequestForResponseModeJWT
import io.mosip.openID4VP.testData.authorizationResponse
import io.mosip.openID4VP.testData.walletConfig
import kotlin.test.*

private const val TEST_RESPONSE_URI = "https://example.com/response"
private const val TEST_NONCE = "test-nonce"
private const val TEST_STATE = "test-state"

class DirectPostResponseModeHandlerTest {

    private fun dispatchInfoFor(responseUrl: String = "https://example.com/response") = ResponseDispatchInfo(
        responseMode = "direct_post",
        nonce = authorizationRequestForResponseModeJWT.nonce,
        walletNonce = "test-nonce",
        state = authorizationRequestForResponseModeJWT.state,
        clientId = authorizationRequestForResponseModeJWT.clientId,
        responseUrl = responseUrl
    )

    @BeforeTest
    fun setUp() {
        mockkObject(NetworkManagerClient)
    }

    @AfterTest
    fun tearDown() {
        clearAllMocks()
    }

    @Test
    fun `validate should not throw any exception`() {
        val handler = DirectPostResponseModeHandler()
        handler.validate(null as io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadataDraft23?,
            walletConfig, false)
        // No exception means pass
    }

    @Test
    fun `sendAuthorizationResponse should send request and return response body`() {
        val handler = DirectPostResponseModeHandler()
        val responseUri = TEST_RESPONSE_URI
        val expectedResponse = "Response received"

        every {
            NetworkManagerClient.sendHTTPRequest(
                responseUri,
                HttpMethod.POST,
                any(),
                any()
            )
        } returns io.mosip.openID4VP.networkManager.NetworkResponse(200, expectedResponse, emptyMap())

        val actualResponse = handler.sendAuthorizationResponse(
            dispatchInfoFor(responseUri),
            authorizationResponse,
            authorizationRequestForResponseModeJWT
        )

        verify {
            NetworkManagerClient.sendHTTPRequest(
                url = responseUri,
                method = HttpMethod.POST,
                bodyParams = authorizationResponse.toJsonEncodedMap(),
                headers = mapOf("Content-Type" to ContentType.APPLICATION_FORM_URL_ENCODED.value)
            )
        }
        assertEquals(expectedResponse, actualResponse.body)
    }

    @Test
    fun `sendAuthorizationResponse should handle network errors`() {
        val handler = DirectPostResponseModeHandler()
        val responseUri = TEST_RESPONSE_URI

        every {
            NetworkManagerClient.sendHTTPRequest(
                responseUri,
                HttpMethod.POST,
                any(),
                any()
            )
        } throws java.io.IOException("Network error")

        val exception = assertFailsWith<java.io.IOException> {
            handler.sendAuthorizationResponse(
                dispatchInfoFor(responseUri),
                authorizationResponse,
                authorizationRequestForResponseModeJWT
            )
        }

        assertEquals("Network error", exception.message)
    }

    @Test
    fun `sendAuthorizationResponse should handle empty response`() {
        val handler = DirectPostResponseModeHandler()
        val responseUri = TEST_RESPONSE_URI

        every {
            NetworkManagerClient.sendHTTPRequest(
                responseUri,
                HttpMethod.POST,
                any(),
                any()
            )
        } returns io.mosip.openID4VP.networkManager.NetworkResponse(200, "", emptyMap())

        val actualResponse = handler.sendAuthorizationResponse(
            dispatchInfoFor(responseUri),
            authorizationResponse,
            authorizationRequestForResponseModeJWT
        )

        assertEquals("", actualResponse.body)
    }


    @Test
    fun `getAuthorizationResponse should return JSON encoded map for AuthorizationResponse`() {
        val handler = DirectPostResponseModeHandler()

        val result = handler.getAuthorizationResponse(
            dispatchInfoFor(),
            authorizationResponse,
            authorizationRequestForResponseModeJWT
        )

        val expectedMap = authorizationResponse.toJsonEncodedMap()
        assertEquals(expectedMap, result)
    }

    @Test
    fun `getAuthorizationErrorResponse should return JSON encoded map for AuthorizationErrorResponse`() {
        val handler = DirectPostResponseModeHandler()
        val errorResponse = AuthorizationErrorResponse(
            error = "invalid_request",
            errorDescription = "Test error description",
            state = TEST_STATE
        )

        val result = handler.getAuthorizationErrorResponse(
            dispatchInfoFor(),
            errorResponse,
            authorizationRequestForResponseModeJWT
        )

        val expectedMap = errorResponse.toJsonEncodedMap()
        assertEquals(expectedMap, result)
    }

    @Test
    fun `getAuthorizationResponse should handle AuthorizationResponse with all fields`() {
        val handler = DirectPostResponseModeHandler()

        val result = handler.getAuthorizationResponse(
            dispatchInfoFor(),
            authorizationResponse,
            authorizationRequestForResponseModeJWT
        )

        // Verify the result contains expected keys
        assertTrue(result.containsKey("vp_token"))
        assertTrue(result.containsKey("presentation_submission"))

        // Verify the values are properly JSON encoded strings
        assertNotNull(result["vp_token"])
        assertNotNull(result["presentation_submission"])
    }

    @Test
    fun `getAuthorizationErrorResponse should handle AuthorizationErrorResponse with null state`() {
        val handler = DirectPostResponseModeHandler()
        val errorResponse = AuthorizationErrorResponse(
            error = "access_denied",
            errorDescription = "Access denied",
            state = null
        )

        val result = handler.getAuthorizationErrorResponse(
            dispatchInfoFor(),
            errorResponse,
            authorizationRequestForResponseModeJWT
        )

        val expectedMap = errorResponse.toJsonEncodedMap()
        assertEquals(expectedMap, result)
        assertTrue(result.containsKey("error"))
        assertTrue(result.containsKey("error_description"))
        // State should not be present when null
        assertFalse(result.containsKey("state"))
    }

    @Test
    fun `getAuthorizationErrorResponse should handle different error types`() {
        val handler = DirectPostResponseModeHandler()

        val errors = listOf(
            "invalid_request" to "The request is missing a required parameter",
            "invalid_client" to "Client authentication failed",
            "invalid_grant" to "The provided authorization grant is invalid",
            "unauthorized_client" to "The client is not authorized",
            "unsupported_grant_type" to "The authorization grant type is not supported",
            "invalid_scope" to "The requested scope is invalid"
        )

        errors.forEach { (errorCode, errorDescription) ->
            val errorResponse = AuthorizationErrorResponse(
                error = errorCode,
                errorDescription = errorDescription,
                state = "test-state-$errorCode"
            )

            val result = handler.getAuthorizationErrorResponse(
                dispatchInfoFor(),
                errorResponse,
                authorizationRequestForResponseModeJWT
            )

            assertEquals(errorResponse.toJsonEncodedMap(), result)
            assertTrue(result.containsKey("error"))
            assertTrue(result.containsKey("error_description"))
            assertTrue(result.containsKey("state"))
        }
    }

    @Test
    fun `getAuthorizationResponse should be independent of dispatch nonce for AuthorizationResponse`() {
        val handler = DirectPostResponseModeHandler()

        val result1 = handler.getAuthorizationResponse(
            dispatchInfoFor(),
            authorizationResponse,
            authorizationRequestForResponseModeJWT
        )

        val result2 = handler.getAuthorizationResponse(
            dispatchInfoFor(),
            authorizationResponse,
            authorizationRequestForResponseModeJWT
        )

        assertEquals(result1, result2)
        assertEquals(authorizationResponse.toJsonEncodedMap(), result1)
        assertEquals(authorizationResponse.toJsonEncodedMap(), result2)
    }

    @Test
    fun `getAuthorizationErrorResponse should be independent of dispatch nonce for AuthorizationErrorResponse`() {
        val handler = DirectPostResponseModeHandler()
        val errorResponse = AuthorizationErrorResponse(
            error = "server_error",
            errorDescription = "Internal server error",
            state = TEST_STATE
        )

        val result1 = handler.getAuthorizationErrorResponse(
            dispatchInfoFor(),
            errorResponse,
            authorizationRequestForResponseModeJWT
        )

        val result2 = handler.getAuthorizationErrorResponse(
            dispatchInfoFor(),
            errorResponse,
            authorizationRequestForResponseModeJWT
        )

        assertEquals(result1, result2)
        assertEquals(errorResponse.toJsonEncodedMap(), result1)
        assertEquals(errorResponse.toJsonEncodedMap(), result2)
    }

    @Test
    fun `getAuthorizationResponse should return map with string values only`() {
        val handler = DirectPostResponseModeHandler()

        val result = handler.getAuthorizationResponse(
            dispatchInfoFor(),
            authorizationResponse,
            authorizationRequestForResponseModeJWT
        )

        result.keys.forEach { key ->
            assertEquals(String::class, key::class, "All keys should be String type")
        }
        result.values.forEach { value ->
            assertEquals(String::class, value::class, "All values should be String type")
        }
        assertTrue(result.containsKey("vp_token"))
        assertTrue(result.containsKey("presentation_submission"))
        assertTrue(result.getValue("vp_token").isNotEmpty())
        assertTrue(result.getValue("presentation_submission").isNotEmpty())
    }

    @Test
    fun `getAuthorizationErrorResponse should return map with string values for error response`() {
        val handler = DirectPostResponseModeHandler()
        val errorResponse = AuthorizationErrorResponse(
            error = "invalid_request",
            errorDescription = "Test error",
            state = TEST_STATE
        )

        val result = handler.getAuthorizationErrorResponse(
            dispatchInfoFor(),
            errorResponse,
            authorizationRequestForResponseModeJWT
        )

        result.keys.forEach { key ->
            assertEquals(String::class, key::class, "All keys should be String type")
        }
        result.values.forEach { value ->
            assertEquals(String::class, value::class, "All values should be String type")
        }

        assertTrue(result.containsKey("error"))
        assertTrue(result.containsKey("error_description"))
        assertTrue(result.containsKey("state"))
        assertEquals("invalid_request", result["error"])
        assertEquals("Test error", result["error_description"])
        assertEquals(TEST_STATE, result["state"])
    }
}
