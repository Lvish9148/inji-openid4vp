package io.mosip.openID4VP.authorizationRequest.presentationDefinition

import io.mockk.clearAllMocks
import io.mosip.openID4VP.authorizationRequest.deserializeAndValidate
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import kotlin.test.*

class ConstraintsTest {

	@BeforeTest
	fun setUp() {
			// Intentionally empty: each test builds its own mocks and input JSON inline,
			// so there is no shared state to initialize before a test runs.
			// Kept for symmetry with tearDown(), which does need to reset mocks afterward.
	}

	@AfterTest
	fun tearDown() {
		// Reset mocks created inline within each test so they don't leak into the next one.
		clearAllMocks()
	}

	@Test
	fun `should throw invalid limit disclosure exception if limit disclosure is present and not matching with predefined values`() {
		val presentationDefinition =
			"""{
                "id":"pd_123",
                "input_descriptors":[
                    {
                        "id":"id_123",
                        "format":{"ldp_vc":{"proof_type":["RsaSignature2018"]}},
                        "constraints":{
                            "fields":[{"path":["$.type"]}],
                            "limit_disclosure": "not preferred"
                        }
                    }
                ]
            }""".trimIndent()

		val expectedExceptionMessage =
			"Invalid Input: constraints->limit_disclosure value should be preferred"

		val actualException = assertFailsWith<OpenID4VPExceptions.InvalidLimitDisclosure> {
			deserializeAndValidate(presentationDefinition, PresentationDefinitionSerializer)
		}

		assertEquals(expectedExceptionMessage, actualException.message)
	}
}
