package com.aandiclub.auth.common.logging

object MaskingUtil {
	private val fullyMaskedKeys = setOf(
		"password",
		"currentpassword",
		"newpassword",
		"accesstoken",
		"refreshtoken",
		"token",
		"temporarypassword",
	)
	private val partiallyMaskedKeys = setOf("loginid")

	fun maskAuthenticate(value: String?): String? {
		if (value.isNullOrBlank()) {
			return null
		}
		return if (value.startsWith("Bearer ", ignoreCase = true)) {
			"Bearer ****"
		} else {
			"****"
		}
	}

	fun sanitizePayload(value: Any?): Any? = sanitizePayload(null, value)

	fun sanitizePayload(key: String?, value: Any?): Any? = when (value) {
		null -> null
		is Map<*, *> -> value.entries.associate { (entryKey, entryValue) ->
			val normalizedKey = entryKey?.toString().orEmpty()
			normalizedKey to sanitizePayload(normalizedKey, entryValue)
		}
		is Collection<*> -> value.map { sanitizePayload(key, it) }
		is Array<*> -> value.map { sanitizePayload(key, it) }
		is String -> sanitizeString(key, value)
		else -> value
	}

	fun sanitizeMessage(message: String?): String? = message
		?.replace(Regex("\\s+"), " ")
		?.trim()
		?.takeUnless { it.isBlank() }

	private fun sanitizeString(key: String?, value: String): String {
		val normalizedKey = key?.lowercase()
		return when {
			normalizedKey == null -> value
			normalizedKey == "authenticate" -> maskAuthenticate(value) ?: "****"
			normalizedKey in fullyMaskedKeys -> "****"
			normalizedKey in partiallyMaskedKeys -> maskLoginId(value)
			else -> value
		}
	}

	private fun maskLoginId(value: String): String {
		if (value.isBlank()) {
			return "****"
		}
		val visibleCount = value.length.coerceAtMost(3)
		return value.take(visibleCount) + "******"
	}
}
