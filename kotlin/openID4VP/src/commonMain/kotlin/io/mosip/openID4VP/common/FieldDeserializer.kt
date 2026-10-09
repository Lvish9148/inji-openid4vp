package io.mosip.openID4VP.common

import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.SerializationException
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.doubleOrNull
import kotlinx.serialization.json.floatOrNull
import kotlinx.serialization.json.intOrNull

class FieldDeserializer(
	private val jsonObject: JsonObject,
	private val className: String,
	private val parentField: String
) {
	fun <T> deserializeField(
		key: String,
		fieldType: String,
		deserializer: DeserializationStrategy<T>? = null,
		isMandatory: Boolean = false,
	): T? {
		val data = jsonObject[key]

		//field is mandatory but it is not present in the input
		if (data == null && isMandatory) {
			throw  OpenID4VPExceptions.MissingInput(listOf(parentField,key),"",className)
		} else if (data == JsonNull) {
			throw OpenID4VPExceptions.InvalidInput(listOf(parentField, key),fieldType,className)

		}
		//field is mandatory but it is not present in the input
		if (data == null) {
			if (isMandatory) {
				throw OpenID4VPExceptions.MissingInput(
					listOf(parentField, key),
					"",
					className
				)
			}
			return null
		}

		if (data == JsonNull) {
			throw OpenID4VPExceptions.InvalidInput(
				listOf(parentField, key),
				fieldType,
				className
			)
		}

		val res = when {
			deserializer != null -> Json.decodeFromJsonElement(
				deserializer,
				data
			) // Custom fields

			fieldType == "String" -> {
				validateFieldType(data, fieldType, parentField, key, className)
				(data as JsonPrimitive).content as T
			}

			fieldType == "Boolean" -> {
				validateFieldType(data, fieldType, parentField, key, className)
				(data as JsonPrimitive).boolean as T
			}

			fieldType.startsWith("List") -> Json.decodeFromJsonElement(
				ListSerializer(String.serializer()),
				data
			) as T

			fieldType.startsWith("Map") -> Json.decodeFromJsonElement<Map<String, JsonElement>>(data)
				.mapValues { (_, value) -> parseDynamicValue(value) } as T

			else -> throw SerializationException("Unsupported field type: $fieldType")
		}

		require(validateField(res, fieldType)) {
			throw OpenID4VPExceptions.InvalidInput(
				listOf(parentField, key),
				fieldType,
				className
			)
		}

		return res
	}

	private fun parseDynamicValue(value: JsonElement): Any {
		return when (value) {
			is JsonPrimitive -> value.booleanOrNull ?: value.intOrNull
			?: value.floatOrNull ?: value.doubleOrNull ?: value.contentOrNull ?: value
			is JsonArray -> value.map { parseDynamicValue(it) }
			is JsonObject -> value.mapValues { parseDynamicValue(it.value) }
			else -> value
		}
	}

	private fun validateFieldType(
		data: JsonElement,
		fieldType: String,
		parentField: String,
		key: String,
		className: String
	) {
		if (data !is JsonPrimitive || when (fieldType) {
				"String" -> !data.isString
				"Boolean" -> (data.booleanOrNull) == null
				else -> true
			}
		) {
			throw  OpenID4VPExceptions.InvalidInput(listOf(parentField, key),fieldType,className)
		}
	}
}