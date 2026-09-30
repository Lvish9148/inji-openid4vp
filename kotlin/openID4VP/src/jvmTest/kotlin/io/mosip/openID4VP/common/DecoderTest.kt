package io.mosip.openID4VP.common

import io.mockk.clearAllMocks
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class DecoderTest {

    @BeforeTest
    fun setUp() {
        // Intentionally empty: decodeFromBase64Url has no static/global state to mock here,
        // so there is nothing to initialize before a test runs.
        // Kept for symmetry with tearDown(), which does need to reset mocks afterward.
    }

    @AfterTest
    fun tearDown() {
        clearAllMocks()
    }

    @Test
    fun `should decode the base64 url encoded content successfully`() {
        val decodedContent = decodeFromBase64Url("aGVsbG8gd29ybGQ=")
        assertEquals("hello world", decodedContent.toString(Charsets.UTF_8))
    }

    @Test
    fun `should throw error when given base64 url encoded data contains non base64 character`() {
        val exception = assertFailsWith<IllegalArgumentException> {
            decodeFromBase64Url("aGVsbG8%d29ybGQ=")
        }

        assertEquals("Illegal base64 character 25", exception.message)
    }

    @Test
    fun `should throw error when given base64 url encoded data has truncated bytes`() {
        val exception = assertFailsWith<IllegalArgumentException> {
            decodeFromBase64Url("aGVsbG8gd29ybG=")
        }

        assertEquals("Input byte array has wrong 4-byte ending unit", exception.message)
    }
}
