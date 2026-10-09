package io.mosip.openID4VP.common

import io.mockk.*
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.*
import kotlin.test.*

class FieldDeserializerTest {


    @AfterTest
    fun tearDown() {
        clearAllMocks()
    }

    @Test
    fun `should deserialize string field successfully`() {
        val jsonObject = buildJsonObject {
            put("testField", JsonPrimitive("testValue"))
        }
        val deserializer = FieldDeserializer(jsonObject, "TestClass", "parentField")
        val result = deserializer.deserializeField<String>("testField", "String")
        assertEquals("testValue", result)
    }

    @Test
    fun `should deserialize boolean field successfully`() {
        val jsonObject = buildJsonObject {
            put("testField", JsonPrimitive(true))
        }
        val deserializer = FieldDeserializer(jsonObject, "TestClass", "parentField")
        val result = deserializer.deserializeField<Boolean>("testField", "Boolean")
        assertEquals(true, result)
    }

    @Test
    fun `should deserialize list field successfully`() {
        val jsonArray = buildJsonArray {
            add(JsonPrimitive("item1"))
            add(JsonPrimitive("item2"))
        }
        val jsonObject = buildJsonObject {
            put("testField", jsonArray)
        }
        val deserializer = FieldDeserializer(jsonObject, "TestClass", "parentField")
        val result = deserializer.deserializeField<List<String>>("testField", "List")
        assertEquals(listOf("item1", "item2"), result)
    }

    @Test
    fun `should deserialize map field successfully`() {
        val nestedObject = buildJsonObject {
            put("nested", JsonPrimitive("value"))
        }
        val jsonObject = buildJsonObject {
            put("testField", buildJsonObject {
                put("key1", JsonPrimitive("value1"))
                put("key2", JsonPrimitive(123))
                put("key3", JsonPrimitive(true))
                put("key4", nestedObject)
            })
        }
        val deserializer = FieldDeserializer(jsonObject, "TestClass", "parentField")
        val result = deserializer.deserializeField<Map<String, Any>>("testField", "Map")

        assertEquals("value1", result?.get("key1"))
        assertEquals(123, result?.get("key2"))
        assertEquals(true, result?.get("key3"))
        assertTrue(result?.get("key4") is Map<*, *>)
        assertEquals("value", (result?.get("key4") as Map<*, *>)["nested"])
    }

    @Test
    fun `should handle nested arrays in map`() {
        val jsonObject = buildJsonObject {
            put("testField", buildJsonObject {
                put("array", buildJsonArray {
                    add(JsonPrimitive("item1"))
                    add(JsonPrimitive("item2"))
                })
            })
        }
        val deserializer = FieldDeserializer(jsonObject, "TestClass", "parentField")
        val result = assertNotNull(
            deserializer.deserializeField<Map<String, Any>>(
                "testField",
                "Map<String, Any>"
            )
        )

        assertTrue(result.get("array") is List<*>)
        assertEquals("item1", (result.get("array") as List<*>)[0])
        assertEquals("item2", (result.get("array") as List<*>)[1])
    }

    @Test
    fun `should return null for optional field that doesn't exist`() {
        val jsonObject = buildJsonObject {}
        val deserializer = FieldDeserializer(jsonObject, "TestClass", "parentField")
        val result = deserializer.deserializeField<String>("nonExistentField", "String", isMandatory = false)
        assertNull(result)
    }

    @Test
    fun `should throw exception when mandatory field is missing`() {
        val jsonObject = buildJsonObject {}
        val deserializer = FieldDeserializer(jsonObject, "TestClass", "parentField")

        val exception = assertFailsWith<OpenID4VPExceptions.MissingInput> {
            deserializer.deserializeField<String>("mandatoryField", "String", isMandatory = true)
        }
        assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST, exception.errorCode)
        assertEquals("Missing Input: parentField->mandatoryField param is required", exception.message)
    }

    @Test
    fun `should throw exception when field value is JsonNull`() {
        val jsonObject = buildJsonObject {
            put("nullField", JsonNull)
        }
        val deserializer = FieldDeserializer(jsonObject, "TestClass", "parentField")

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidInput> {
            deserializer.deserializeField<String>("nullField", "String")
        }
        assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST, exception.errorCode)
        assertEquals("Invalid Input: parentField->nullField value cannot be an empty string, null, or an integer", exception.message)
    }

    @Test
    fun `should throw exception when string field type is incorrect`() {
        val jsonObject = buildJsonObject {
            put("stringField", JsonPrimitive(123))
        }
        val deserializer = FieldDeserializer(jsonObject, "TestClass", "parentField")

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidInput> {
            deserializer.deserializeField<String>("stringField", "String")
        }
        assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST, exception.errorCode)
        assertEquals("Invalid Input: parentField->stringField value cannot be an empty string, null, or an integer", exception.message)
    }

    @Test
    fun `should throw exception when boolean field type is incorrect`() {
        val jsonObject = buildJsonObject {
            put("booleanField", JsonPrimitive("not-a-boolean"))
        }
        val deserializer = FieldDeserializer(jsonObject, "TestClass", "parentField")

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidInput> {
            deserializer.deserializeField<Boolean>("booleanField", "Boolean")
        }
        assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST, exception.errorCode)
        assertEquals("Invalid Input: parentField->booleanField value must be either true or false", exception.message)
    }

    @Test
    fun `should throw exception for unsupported field type`() {
        val jsonObject = buildJsonObject {
            put("testField", JsonPrimitive("value"))
        }
        val deserializer = FieldDeserializer(jsonObject, "TestClass", "parentField")

        val exception = assertFailsWith<SerializationException> {
            deserializer.deserializeField<Any>("testField", "UnsupportedType")
        }
        assertTrue(exception.message!!.contains("Unsupported field type"))
    }

    @Test
    fun `should use custom deserializer when provided`() {
        val jsonObject = buildJsonObject {
            put("testField", JsonPrimitive("custom"))
        }
        val deserializer = FieldDeserializer(jsonObject, "TestClass", "parentField")
        val customDeserializer = mockk<DeserializationStrategy<String>>()

        every { customDeserializer.deserialize(any()) } returns "deserialized value"

        val result = deserializer.deserializeField("testField", "CustomType", customDeserializer)
        assertEquals("deserialized value", result)
    }
}