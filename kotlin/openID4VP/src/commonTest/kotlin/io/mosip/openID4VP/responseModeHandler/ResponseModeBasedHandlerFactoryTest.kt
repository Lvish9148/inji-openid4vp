package io.mosip.openID4VP.responseModeHandler

import io.mosip.openID4VP.constants.ResponseMode
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions.InvalidData
import io.mosip.openID4VP.responseModeHandler.types.DirectPostJwtResponseModeHandler
import io.mosip.openID4VP.responseModeHandler.types.DirectPostResponseModeHandler
import kotlin.test.*

class ResponseModeBasedHandlerFactoryTest {

    @Test
    fun `get should return DirectPostResponseModeHandler for direct_post mode`() {
        val handler = ResponseModeBasedHandlerFactory.get(ResponseMode.DIRECT_POST.value)

        assertTrue(handler is DirectPostResponseModeHandler)
        assertNotNull(handler)
    }



    @Test
    fun `get should return DirectPostResponseModeHandler for iar_post mode`() {
        val handler = ResponseModeBasedHandlerFactory.get(ResponseMode.IAR_POST.value)

        assertTrue(handler is DirectPostResponseModeHandler)
        assertNotNull(handler)
    }


    @Test
    fun `get should return DirectPostJwtResponseModeHandler for direct_post_jwt mode`() {
        val handler = ResponseModeBasedHandlerFactory.get(ResponseMode.DIRECT_POST_JWT.value)

        assertTrue(handler is DirectPostJwtResponseModeHandler)
        assertNotNull(handler)
    }

    @Test
    fun `get should return DirectPostJwtResponseModeHandler for iar_post_jwt mode`() {
        val handler = ResponseModeBasedHandlerFactory.get(ResponseMode.IAR_POST_JWT.value)

        assertTrue(handler is DirectPostJwtResponseModeHandler)
        assertNotNull(handler)
    }

    @Test
    fun `get should return new instances each time for direct_post mode`() {
        val handler1 = ResponseModeBasedHandlerFactory.get(ResponseMode.DIRECT_POST.value)
        val handler2 = ResponseModeBasedHandlerFactory.get(ResponseMode.DIRECT_POST.value)

        assertTrue(handler1 is DirectPostResponseModeHandler)
        assertTrue(handler2 is DirectPostResponseModeHandler)
        assertNotSame(handler1, handler2, "Factory should return new instances each time")
    }

    @Test
    fun `get should return new instances each time for direct_post_jwt mode`() {
        val handler1 = ResponseModeBasedHandlerFactory.get(ResponseMode.DIRECT_POST_JWT.value)
        val handler2 = ResponseModeBasedHandlerFactory.get(ResponseMode.DIRECT_POST_JWT.value)

        assertTrue(handler1 is DirectPostJwtResponseModeHandler)
        assertTrue(handler2 is DirectPostJwtResponseModeHandler)
        assertNotSame(handler1, handler2, "Factory should return new instances each time")
    }

    @Test
    fun `get should handle response mode with extra whitespace`() {
        val modeWithSpaces = " ${ResponseMode.DIRECT_POST.value} "

        val exception = assertFailsWith<InvalidData> {
            ResponseModeBasedHandlerFactory.get(modeWithSpaces)
        }
        assertEquals(
            "Given response_mode - $modeWithSpaces is not supported",
            exception.message
        )
    }

   @Test
fun `get should validate all supported response mode constants`() {
    // Test all direct_post variants
    val directPostHandler = ResponseModeBasedHandlerFactory.get("direct_post")
    assertTrue(directPostHandler is DirectPostResponseModeHandler)

    val iarPostHandler = ResponseModeBasedHandlerFactory.get("iar-post")
    assertTrue(iarPostHandler is DirectPostResponseModeHandler)

    val iaePostHandler = ResponseModeBasedHandlerFactory.get("iae_post")
    assertTrue(iaePostHandler is DirectPostResponseModeHandler)

    // Test all JWT variants
    val directPostJwtHandler = ResponseModeBasedHandlerFactory.get("direct_post.jwt")
    assertTrue(directPostJwtHandler is DirectPostJwtResponseModeHandler)

    val iarPostJwtHandler = ResponseModeBasedHandlerFactory.get("iar-post.jwt")
    assertTrue(iarPostJwtHandler is DirectPostJwtResponseModeHandler)

    val iaePostJwtHandler = ResponseModeBasedHandlerFactory.get("iae_post.jwt")
    assertTrue(iaePostJwtHandler is DirectPostJwtResponseModeHandler)
}

    @Test
    fun `should throw InvalidData exception for unsupported or invalid response mode`() {
        val similarModes = listOf(
            ResponseMode.DIRECT_POST.value.uppercase(),
            "   ",
            "",
            "null",
            "unsupported_mode",
            "direct-post",      // dash instead of underscore
            "directpost",       // no separator
            "direct_post_jwt",  // underscore instead of dot
            "direct_post_json", // json instead of jwt
            "post_direct",      // reversed order
            "direct_get",       // get instead of post
            "indirect_post"     // indirect instead of direct
        )

        similarModes.forEach { mode ->
            val exception = assertFailsWith<InvalidData> {
                ResponseModeBasedHandlerFactory.get(mode)
            }
            assertEquals(
                "Given response_mode - $mode is not supported",
                exception.message
            )
        }
    }

    @Test
    fun `factory should be singleton object`() {
        val factory1 = ResponseModeBasedHandlerFactory
        val factory2 = ResponseModeBasedHandlerFactory

        assertSame(factory1, factory2, "Factory should be a singleton object")
    }
}
