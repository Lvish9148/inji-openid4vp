package io.mosip.openID4VP.authorizationRequest.presentationDefinition

import io.mockk.clearAllMocks
import io.mosip.openID4VP.authorizationRequest.deserializeAndValidate
import io.mosip.openID4VP.common.OpenID4VPErrorCodes
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions

import kotlin.test.*

class FieldsTest {
	private lateinit var presentationDefinition: String
	private lateinit var expectedExceptionMessage: String

	@BeforeTest
	fun setUp() {
			// Intentionally empty: each test assigns presentationDefinition and expectedExceptionMessage
			// itself, so there is no shared state to initialize before a test runs.
			// Kept for symmetry with tearDown(), which does need to reset mocks afterward.
	}

	@AfterTest
	fun tearDown() {
		// Reset mocks created inline within each test so they don't leak into the next one.
		clearAllMocks()
	}

	@Test
	fun `should throw invalid input pattern exception for invalid path param prefix`() {
		presentationDefinition =
			"""{"id":"pd_123","input_descriptors":[{"id":"id_123","constraints":{"fields":[{"path":["$-type"]}]}}]}"""
		expectedExceptionMessage =
			"Invalid Input Pattern: fields->path pattern is not matching with OpenId4VP specification"

		val actualException =
			assertFailsWith<OpenID4VPExceptions.InvalidInputPattern> {
				deserializeAndValidate(presentationDefinition, PresentationDefinitionSerializer)
			}
		assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST, actualException.errorCode)
		assertEquals(expectedExceptionMessage, actualException.message)
	}

	@Test
	fun `should throw missing input exception if path param is missing`() {
		presentationDefinition =
			"""{"id":"pd_123","input_descriptors":[{"id":"id_123","constraints":{"fields":[{}]}}]}"""
		expectedExceptionMessage = "Missing Input: fields->path param is required"

		val actualException =

				assertFailsWith<OpenID4VPExceptions.MissingInput> {
				deserializeAndValidate(presentationDefinition, PresentationDefinitionSerializer)
			}
		assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST, actualException.errorCode)
		assertEquals(expectedExceptionMessage, actualException.message)
	}

	@Test
	fun `should throw invalid input exception if path param is empty`() {
		presentationDefinition =
			"""{"id":"pd_123","input_descriptors":[{"id":"id_123","constraints":{"fields":[{"path":[]}]}}]}"""
		expectedExceptionMessage = "Invalid Input: fields->path value cannot be empty or null"

		val actualException =
			assertFailsWith<OpenID4VPExceptions.InvalidInput> {
				deserializeAndValidate(presentationDefinition, PresentationDefinitionSerializer)
			}
		assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST, actualException.errorCode)
		assertEquals(expectedExceptionMessage, actualException.message)
	}

	@Test
	fun `should throw invalid input exception if path param is present but it's value is null`() {
		presentationDefinition =
			"""{"id":"pd_123","input_descriptors":[{"id":"id_123","constraints":{"fields":[{"path":null}]}}]}"""
		expectedExceptionMessage = "Invalid Input: fields->path value cannot be empty or null"

		val actualException =
			assertFailsWith<OpenID4VPExceptions.InvalidInput> {
				deserializeAndValidate(presentationDefinition, PresentationDefinitionSerializer)
			}
		assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST, actualException.errorCode)
		assertEquals(expectedExceptionMessage, actualException.message)
	}
}
