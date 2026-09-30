package io.mosip.openID4VP.dcql.query

import io.mosip.openID4VP.common.OpenID4VPErrorCodes
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.testData.assertOpenId4VPException
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertIs
import kotlin.test.assertTrue
import io.mosip.openID4VP.constants.FormatType

private const val EMPLOYEE_CARD = "employee-card"
private const val VC_SD_JWT = "vc+sd-jwt"
private const val GIVEN_NAME = "given-name"

class DCQLQueryTest {

    @Test
    fun `should serialize and deserialize dcql query correctly`() {
        val query = DCQLQuery(
            credentials = listOf(
                CredentialQuery(
                    id = EMPLOYEE_CARD,
                    format = VC_SD_JWT,
                    multiple = true,
                    meta = mapOf(
                        "vct_values" to listOf("EmployeeCardCredential"),
                        "priority" to 1,
                        "holder_binding_required" to true,
                        "nested" to mapOf("level" to "gold")
                    ),
                    requireCryptographicHolderBinding = false,
                    claims = listOf(
                        ClaimsQuery(
                            id = GIVEN_NAME,
                            path = listOf("credentialSubject", "given_name", null, 0),
                            values = listOf(
                                ClaimValue.StringValue("Alice"),
                                ClaimValue.LongValue(1),
                                ClaimValue.BoolValue(true)
                            )
                        )
                    ),
                    claimSets = listOf(listOf(GIVEN_NAME))
                ),
                CredentialQuery(
                    id = "licence",
                    format = "mso_mdoc",
                    meta = mapOf("doctype_value" to "org.iso.18013.5.1.mDL")
                )
            ),
            credentialSets = listOf(
                CredentialSetQuery(
                    options = listOf(listOf(EMPLOYEE_CARD), listOf("licence")),
                    required = false
                )
            )
        )

        val json = Json.encodeToString(DCQLQuerySerializer, query)
        val decoded = Json.decodeFromString(DCQLQuerySerializer, json)

        assertEquals(query, decoded)
        assertTrue(json.contains("\"credential_sets\""))
        assertTrue(json.contains("\"claim_sets\""))
        assertTrue(json.contains("\"require_cryptographic_holder_binding\":false"))
    }

    @Test
    fun `should deserialize using serializer with defaults and typed values`() {
        val json = """
            {
              "credentials": [
                {
                  "id": "cred1",
                  "format": "$VC_SD_JWT",
                  "meta": {
                    "priority": 2,
                    "holder_binding_required": true,
                    "labels": ["alpha", "beta"]
                  },
                  "claims": [
                    {
                      "id": "$GIVEN_NAME",
                      "path": ["credentialSubject", "given_name"],
                      "values": ["Alice", 42, true]
                    }
                  ],
                  "claim_sets": [["$GIVEN_NAME"]]
                }
              ]
            }
        """.trimIndent()

        val query = Json.decodeFromString(DCQLQuerySerializer, json)
        val credential = query.credentials.first()
        val claims = credential.claims!!.first()

        assertFalse(credential.multiple)
        assertTrue(credential.requireCryptographicHolderBinding)
        assertEquals(2, credential.meta["priority"])
        assertEquals(true, credential.meta["holder_binding_required"])
        assertEquals(listOf("alpha", "beta"), credential.meta["labels"])
        assertEquals(listOf(GIVEN_NAME), credential.claimSets!!.first())
        assertIs<ClaimValue.StringValue>(claims.values!![0])
        assertIs<ClaimValue.LongValue>(claims.values[1])
        assertIs<ClaimValue.BoolValue>(claims.values[2])
    }

    @Test
    fun `should serialize with expected field names and omit default optional fields`() {
        val query = DCQLQuery(
            credentials = listOf(
                CredentialQuery(
                    id = "cred1",
                    format = VC_SD_JWT,
                    claims = listOf(
                        ClaimsQuery(
                            id = "name",
                            path = listOf("credentialSubject", "name")
                        )
                    ),
                    claimSets = listOf(listOf("name"))
                )
            )
        )

        val json = Json.encodeToString(DCQLQuerySerializer, query)

        assertTrue(json.contains("\"claim_sets\""))
        assertTrue(json.contains("\"meta\":{}"))
        assertFalse(json.contains("\"multiple\""))
        assertFalse(json.contains("\"require_cryptographic_holder_binding\""))
    }

    @Test
    fun `should throw json encoding failure when meta contains non string nested key`() {
        val query = DCQLQuery(
            credentials = listOf(
                CredentialQuery(
                    id = "cred1",
                    format = VC_SD_JWT,
                    meta = mapOf("nested" to mapOf(1 to "value"))
                )
            )
        )

        val exception = assertFailsWith<OpenID4VPExceptions.JsonEncodingFailed> {
            Json.encodeToString(DCQLQuerySerializer, query)
        }

        assertTrue(exception.message!!.contains("Only string keys are supported"))
        assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST, exception.errorCode)
    }

    @Test
    fun `should create valid query with single credential query`() {
        val query = DCQLQuery(
            credentials = listOf(
                CredentialQuery(
                    id = EMPLOYEE_CARD,
                    format = VC_SD_JWT,
                    claims = listOf(ClaimsQuery(path = listOf("given_name")))
                )
            )
        )

        assertEquals(1, query.credentials.size)
        assertEquals(EMPLOYEE_CARD, query.credentials.first().id)
        assertNull(query.credentialSets)
    }

    @Test
    fun `should create valid query with multiple credential queries`() {
        val query = DCQLQuery(
            credentials = listOf(
                CredentialQuery(id = "sdjwt", format = VC_SD_JWT),
                CredentialQuery(id = "mdoc", format = "mso_mdoc", multiple = true)
            )
        )

        assertEquals(2, query.credentials.size)
        assertTrue(query.credentials.last().multiple)
    }

    @Test
    fun `should create valid query with credential sets`() {
        val query = DCQLQuery(
            credentials = listOf(
                CredentialQuery(id = "sdjwt", format = VC_SD_JWT),
                CredentialQuery(id = "mdoc", format = "mso_mdoc")
            ),
            credentialSets = listOf(
                CredentialSetQuery(options = listOf(listOf("sdjwt"), listOf("mdoc")))
            )
        )

        assertNotNull(query.credentialSets)
        assertEquals(1, query.credentialSets.size)
        assertTrue(query.credentialSets.first().required)
    }

    @Test
    fun `should throw when credentials list is empty`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidInput> {
            DCQLQuery(credentials = emptyList())
        }

        assertOpenId4VPException(
            exception,
            "Invalid Input: dcql_query->credentials value cannot be empty or null",
            OpenID4VPErrorCodes.INVALID_REQUEST
        )
    }

    @Test
    fun `should throw when credential query ids are duplicated`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            DCQLQuery(
                credentials = listOf(
                    CredentialQuery(id = "duplicate", format = VC_SD_JWT),
                    CredentialQuery(id = "duplicate", format = "mso_mdoc")
                )
            )
        }

        assertOpenId4VPException(
            exception,
            "Credential Query ids must be unique within dcql_query",
            OpenID4VPErrorCodes.INVALID_REQUEST
        )
    }

    @Test
    fun `should throw when credential set references unknown query id`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            DCQLQuery(
                credentials = listOf(CredentialQuery(id = "known", format = VC_SD_JWT)),
                credentialSets = listOf(CredentialSetQuery(options = listOf(listOf("unknown"))))
            )
        }

        assertOpenId4VPException(
            exception,
            "credential_sets references unknown credential id 'unknown'",
            OpenID4VPErrorCodes.INVALID_REQUEST
        )
    }

    @Test
    fun `should validate claims query with valid path components`() {
        val claimsQuery = ClaimsQuery(
            id = "degree",
            path = listOf("credentialSubject", "degrees", null, 0),
            values = listOf(ClaimValue.StringValue("Bachelor"))
        )

        claimsQuery.validate(isClaimSetsAvailable = true)

        assertEquals(4, claimsQuery.path.size)
        assertFalse(claimsQuery.values.isNullOrEmpty())
    }

    @Test
    fun `should throw when claims query path is empty`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidInput> {
            ClaimsQuery(path = emptyList()).validate(isClaimSetsAvailable = false)
        }

        assertOpenId4VPException(
            exception,
            "Invalid Input: claims_query->path value cannot be empty or null",
            OpenID4VPErrorCodes.INVALID_REQUEST
        )
    }

    @Test
    fun `ClaimValue from should return StringValue for string input`() {
        val result = ClaimValue.from("hello")

        assertEquals(ClaimValue.StringValue("hello"), result)
    }

    @Test
    fun `ClaimValue from should return LongValue for int input`() {
        val result = ClaimValue.from(42)

        assertEquals(ClaimValue.LongValue(42L), result)
    }

    @Test
    fun `ClaimValue from should return LongValue for long input`() {
        val result = ClaimValue.from(100L)

        assertEquals(ClaimValue.LongValue(100L), result)
    }

    @Test
    fun `ClaimValue from should return BoolValue for true boolean input`() {
        val result = ClaimValue.from(true)

        assertEquals(ClaimValue.BoolValue(true), result)
    }

    @Test
    fun `ClaimValue from should return BoolValue for false boolean input`() {
        val result = ClaimValue.from(false)

        assertEquals(ClaimValue.BoolValue(false), result)
    }

    @Test
    fun `ClaimValue from should throw for null input`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            ClaimValue.from(null)
        }

        assertOpenId4VPException(
            exception,
            "Claim value must be a string, integer, or boolean",
            OpenID4VPErrorCodes.INVALID_REQUEST
        )
    }

    @Test
    fun `ClaimValue from should throw for unsupported type input`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            ClaimValue.from(listOf("unsupported"))
        }

        assertOpenId4VPException(
            exception,
            "Claim value must be a string, integer, or boolean",
            OpenID4VPErrorCodes.INVALID_REQUEST
        )
    }

    private val sdJwt = FormatType.VC_SD_JWT.value

    @Test
    fun `rejects a credential query id with disallowed characters`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            DCQLQuery(credentials = listOf(CredentialQuery(id = "not valid!", format = sdJwt)))
        }
        assertEquals(
            "Credential Query id must consist of alphanumeric, underscore or hyphen characters",
            exception.message
        )
    }

    @Test
    fun `accepts credential query ids of alphanumerics underscores and hyphens`() {
        val query = DCQLQuery(
            credentials = listOf(CredentialQuery(id = "employee_card-1", format = sdJwt))
        )

        assertEquals("employee_card-1", query.credentials.single().id)
    }

    @Test
    fun `rejects a blank credential query format`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidInput> {
            DCQLQuery(credentials = listOf(CredentialQuery(id = "card", format = "   ")))
        }
        assertEquals(
            "Invalid Input: credential_query->format value cannot be empty or null",
            exception.message
        )
    }

    @Test
    fun `rejects an empty claims list`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidInput> {
            DCQLQuery(
                credentials = listOf(
                    CredentialQuery(id = "card", format = sdJwt, claims = emptyList())
                )
            )
        }
        assertEquals(
            "Invalid Input: credential_query->claims value cannot be empty or null",
            exception.message
        )
    }

    @Test
    fun `rejects duplicate claim ids within a credential query`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            DCQLQuery(
                credentials = listOf(
                    CredentialQuery(
                        id = "card",
                        format = sdJwt,
                        claims = listOf(
                            ClaimsQuery(id = "name", path = listOf("given_name")),
                            ClaimsQuery(id = "name", path = listOf("family_name"))
                        )
                    )
                )
            )
        }
        assertEquals("Claim ids must be unique within a Credential Query", exception.message)
    }

    @Test
    fun `rejects claim_sets when claims is absent`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            DCQLQuery(
                credentials = listOf(
                    CredentialQuery(id = "card", format = sdJwt, claimSets = listOf(listOf("name")))
                )
            )
        }
        assertEquals("claim_sets must not be present when claims is absent", exception.message)
    }

    @Test
    fun `rejects an empty claim_sets list`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidInput> {
            DCQLQuery(
                credentials = listOf(
                    CredentialQuery(
                        id = "card",
                        format = sdJwt,
                        claims = listOf(ClaimsQuery(id = "name", path = listOf("given_name"))),
                        claimSets = emptyList()
                    )
                )
            )
        }
        assertEquals(
            "Invalid Input: credential_query->claim_sets value cannot be empty or null",
            exception.message
        )
    }

    @Test
    fun `rejects an empty claim_sets option`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidInput> {
            DCQLQuery(
                credentials = listOf(
                    CredentialQuery(
                        id = "card",
                        format = sdJwt,
                        claims = listOf(ClaimsQuery(id = "name", path = listOf("given_name"))),
                        claimSets = listOf(emptyList())
                    )
                )
            )
        }
        assertEquals(
            "Invalid Input: credential_query->claim_sets value cannot be empty or null",
            exception.message
        )
    }

    @Test
    fun `rejects claim_sets referencing an unknown claim id`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            DCQLQuery(
                credentials = listOf(
                    CredentialQuery(
                        id = "card",
                        format = sdJwt,
                        claims = listOf(ClaimsQuery(id = "name", path = listOf("given_name"))),
                        claimSets = listOf(listOf("unknown"))
                    )
                )
            )
        }
        assertEquals("claim_sets references unknown claim id 'unknown'", exception.message)
    }

    @Test
    fun `requires every claim to carry an id when claim_sets is present`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            DCQLQuery(
                credentials = listOf(
                    CredentialQuery(
                        id = "card",
                        format = sdJwt,
                        claims = listOf(ClaimsQuery(path = listOf("given_name"))),
                        claimSets = listOf(listOf("name"))
                    )
                )
            )
        }
        assertEquals("Claims with claim_sets must have an id", exception.message)
    }

    @Test
    fun `rejects a claims query id with disallowed characters`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            DCQLQuery(
                credentials = listOf(
                    CredentialQuery(
                        id = "card",
                        format = sdJwt,
                        claims = listOf(ClaimsQuery(id = "bad id", path = listOf("given_name")))
                    )
                )
            )
        }
        assertEquals(
            "Claims Query id must consist of alphanumeric, underscore or hyphen characters",
            exception.message
        )
    }

    @Test
    fun `rejects an empty claims query values list`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidInput> {
            DCQLQuery(
                credentials = listOf(
                    CredentialQuery(
                        id = "card",
                        format = sdJwt,
                        claims = listOf(ClaimsQuery(path = listOf("given_name"), values = emptyList()))
                    )
                )
            )
        }
        assertEquals(
            "Invalid Input: claims_query->values value cannot be empty or null",
            exception.message
        )
    }

    @Test
    fun `rejects an empty credential_sets list`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidInput> {
            DCQLQuery(
                credentials = listOf(CredentialQuery(id = "card", format = sdJwt)),
                credentialSets = emptyList()
            )
        }
        assertEquals(
            "Invalid Input: dcql_query->credential_sets value cannot be empty or null",
            exception.message
        )
    }

    @Test
    fun `rejects a credential set with no options`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidInput> {
            CredentialSetQuery(options = emptyList())
        }
        assertEquals(
            "Invalid Input: credential_set_query->options value cannot be empty or null",
            exception.message
        )
    }

    @Test
    fun `rejects a credential set option with no credential ids`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidInput> {
            CredentialSetQuery(options = listOf(emptyList()))
        }
        assertEquals(
            "Invalid Input: credential_set_query->options value cannot be empty or null",
            exception.message
        )
    }

    private fun decode(json: String): DCQLQuery = Json.decodeFromString(DCQLQuerySerializer, json)

    private fun credential(body: String) = """{"credentials":[$body]}"""

    @Test
    fun `rejects a dcql_query that is not a json object`() {
        val exception = assertFailsWith<OpenID4VPExceptions.DeserializationFailure> {
            decode(""""a string"""")
        }
        assertTrue(exception.message.startsWith("Deserializing for [dcql_query] failed"))
    }

    @Test
    fun `requires the credentials member`() {
        val exception = assertFailsWith<OpenID4VPExceptions.MissingInput> { decode("{}") }
        assertEquals("Missing Input: dcql_query->credentials param is required", exception.message)
    }

    @Test
    fun `requires credentials to be an array`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidInput> {
            decode("""{"credentials":{}}""")
        }
        assertEquals(
            "Invalid Input: dcql_query->credentials value cannot be empty or null",
            exception.message
        )
    }

    @Test
    fun `requires each credential entry to be an object`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidInput> {
            decode("""{"credentials":["not-an-object"]}""")
        }
        assertEquals(
            "Invalid Input: dcql_query->credentials->0 value cannot be empty or null",
            exception.message
        )
    }

    @Test
    fun `requires credential_sets to be an array of objects`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidInput> {
            decode(
                """{"credentials":[{"id":"c1","format":"vc+sd-jwt"}],"credential_sets":["nope"]}"""
            )
        }
        assertEquals(
            "Invalid Input: dcql_query->credential_sets->0 value cannot be empty or null",
            exception.message
        )
    }

    @Test
    fun `requires the credential query id`() {
        val exception = assertFailsWith<OpenID4VPExceptions.MissingInput> {
            decode(credential("""{"format":"vc+sd-jwt"}"""))
        }
        assertEquals("Missing Input: credential_query->id param is required", exception.message)
    }

    @Test
    fun `requires the credential query id to be a string`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidInput> {
            decode(credential("""{"id":42,"format":"vc+sd-jwt"}"""))
        }
        assertEquals(
            "Invalid Input: credential_query->id value cannot be an empty string, null, or an integer",
            exception.message
        )
    }

    @Test
    fun `requires the credential query format`() {
        val exception = assertFailsWith<OpenID4VPExceptions.MissingInput> {
            decode(credential("""{"id":"c1"}"""))
        }
        assertEquals("Missing Input: credential_query->format param is required", exception.message)
    }

    @Test
    fun `rejects a null credential query id`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidInput> {
            decode(credential("""{"id":null,"format":"vc+sd-jwt"}"""))
        }
        assertEquals(
            "Invalid Input: credential_query->id value cannot be an empty string, null, or an integer",
            exception.message
        )
    }

    @Test
    fun `requires multiple to be a boolean`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidInput> {
            decode(credential("""{"id":"c1","format":"vc+sd-jwt","multiple":"yes"}"""))
        }
        assertEquals(
            "Invalid Input: credential_query->multiple value must be either true or false",
            exception.message
        )
    }

    @Test
    fun `requires meta to be an object`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidInput> {
            decode(credential("""{"id":"c1","format":"vc+sd-jwt","meta":"nope"}"""))
        }
        assertEquals(
            "Invalid Input: credential_query->meta value cannot be empty or null",
            exception.message
        )
    }

    @Test
    fun `requires claim_sets entries to be arrays of strings`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidInput> {
            decode(
                credential(
                    """{"id":"c1","format":"vc+sd-jwt","claims":[{"id":"n","path":["a"]}],"claim_sets":[[7]]}"""
                )
            )
        }
        assertEquals(
            "Invalid Input: credential_query->claim_sets->0->0 value cannot be an empty string, null, or an integer",
            exception.message
        )
    }

    @Test
    fun `requires credential_set options to be arrays of strings`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidInput> {
            decode(
                """{"credentials":[{"id":"c1","format":"vc+sd-jwt"}],"credential_sets":[{"options":[[7]]}]}"""
            )
        }
        assertEquals(
            "Invalid Input: credential_set_query->options->0->0 value cannot be an empty string, null, or an integer",
            exception.message
        )
    }

    @Test
    fun `applies the documented defaults`() {
        val query = decode(credential("""{"id":"c1","format":"vc+sd-jwt"}"""))

        val credential = query.credentials.single()
        assertEquals(false, credential.multiple)
        assertEquals(emptyMap(), credential.meta)
        assertTrue(credential.requireCryptographicHolderBinding)
        assertNull(credential.claims)
        assertNull(credential.claimSets)
        assertNull(query.credentialSets)
    }

    @Test
    fun `honours an explicit require_cryptographic_holder_binding false`() {
        val query = decode(
            credential("""{"id":"c1","format":"vc+sd-jwt","require_cryptographic_holder_binding":false}""")
        )

        assertEquals(false, query.credentials.single().requireCryptographicHolderBinding)
    }

    @Test
    fun `decodes meta values of every json primitive type`() {
        val query = decode(
            credential(
                """{"id":"c1","format":"vc+sd-jwt","meta":{
                  "text":"a","flag":true,"count":3,"big":9000000000,"ratio":1.5,
                  "nothing":null,"list":["x",1],"nested":{"inner":"v"}
                }}"""
            )
        )

        val meta = query.credentials.single().meta
        assertEquals("a", meta["text"])
        assertEquals(true, meta["flag"])
        assertEquals(3, meta["count"])
        assertEquals(9_000_000_000L, meta["big"])
        assertEquals(1.5f, meta["ratio"])
        assertEquals(listOf("x", 1), meta["list"])
        assertEquals(mapOf("inner" to "v"), meta["nested"])
    }

    @Test
    fun `decodes claim values of every supported type`() {
        val query = decode(
            credential(
                """{"id":"c1","format":"vc+sd-jwt","claims":[
                  {"path":["a"],"values":["text",7,true]}
                ]}"""
            )
        )

        assertEquals(
            listOf(
                ClaimValue.StringValue("text"),
                ClaimValue.LongValue(7L),
                ClaimValue.BoolValue(true)
            ),
            query.credentials.single().claims!!.single().values
        )
    }

    @Test
    fun `round trips a query through encode and decode`() {
        val json = """{"credentials":[{"id":"c1","format":"vc+sd-jwt","meta":{"vct_values":["employee"]},
            "multiple":true,"require_cryptographic_holder_binding":false,
            "claims":[{"id":"n","path":["given_name",0,null],"values":["Alice"]}],
            "claim_sets":[["n"]]}],
            "credential_sets":[{"options":[["c1"]],"required":false}]}"""

        val encoded = Json.encodeToString(DCQLQuerySerializer, decode(json))

        assertTrue(encoded.contains("\"multiple\":true"))
        assertTrue(encoded.contains("\"require_cryptographic_holder_binding\":false"))
        assertTrue(encoded.contains("\"claim_sets\":[[\"n\"]]"))
        assertTrue(encoded.contains("\"required\":false"))
        assertTrue(encoded.contains("\"path\":[\"given_name\",0,null]"))
        assertEquals(decode(json), decode(encoded))
    }

    @Test
    fun `omits defaulted optional fields when encoding`() {
        val encoded = Json.encodeToString(
            DCQLQuerySerializer,
            decode(credential("""{"id":"c1","format":"vc+sd-jwt"}"""))
        )

        assertEquals(false, encoded.contains("multiple"))
        assertEquals(false, encoded.contains("require_cryptographic_holder_binding"))
        assertEquals(false, encoded.contains("credential_sets"))
    }

    @Test
    fun `rejects meta values that cannot be serialized`() {
        val query = DCQLQuery(
            credentials = listOf(
                CredentialQuery(id = "c1", format = "vc+sd-jwt", meta = mapOf("bad" to Any()))
            )
        )

        val exception = assertFailsWith<OpenID4VPExceptions.JsonEncodingFailed> {
            Json.encodeToString(DCQLQuerySerializer, query)
        }
        assertTrue(exception.message.contains("Unsupported value type 'Any'"))
    }

    @Test
    fun `rejects meta objects with non-string keys`() {
        val query = DCQLQuery(
            credentials = listOf(
                CredentialQuery(id = "c1", format = "vc+sd-jwt", meta = mapOf("bad" to mapOf(1 to "v")))
            )
        )

        val exception = assertFailsWith<OpenID4VPExceptions.JsonEncodingFailed> {
            Json.encodeToString(DCQLQuerySerializer, query)
        }
        assertTrue(
            exception.message.contains("Only string keys are supported while serializing dynamic JSON objects")
        )
    }

    @Test
    fun `rejects a credential query id that is not a json primitive`() {
        val json = """
            {
              "credentials": [
                { "id": { "value": "cred1" }, "format": "vc+sd-jwt" }
              ]
            }
        """.trimIndent()

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidInput> {
            Json.decodeFromString(DCQLQuerySerializer, json)
        }
        assertOpenId4VPException(
            exception,
            "Invalid Input: credential_query->id value cannot be an empty string, null, or an integer",
            OpenID4VPErrorCodes.INVALID_REQUEST
        )
    }

    @Test
    fun `deserializes a credential query that opts out of cryptographic holder binding`() {
        val json = """
            {
              "credentials": [
                {
                  "id": "cred1",
                  "format": "vc+sd-jwt",
                  "require_cryptographic_holder_binding": false
                }
              ],
              "credential_sets": [
                { "options": [["cred1"]], "required": false }
              ]
            }
        """.trimIndent()

        val query = Json.decodeFromString(DCQLQuerySerializer, json)

        assertFalse(query.credentials.first().requireCryptographicHolderBinding)
        assertFalse(query.credentialSets!!.first().required)
    }

    @Test
    fun `rejects a dcql query that is not a json object`() {
        val exception = assertFailsWith<OpenID4VPExceptions.DeserializationFailure> {
            Json.decodeFromString(DCQLQuerySerializer, """["not-an-object"]""")
        }
        assertOpenId4VPException(
            exception,
            "Deserializing for [dcql_query] failed due to this error: " +
                "Element class kotlinx.serialization.json.JsonArray is not a JsonObject",
            OpenID4VPErrorCodes.INVALID_REQUEST
        )
    }
}
