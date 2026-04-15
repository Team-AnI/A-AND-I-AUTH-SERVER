package com.aandiclub.auth.common.logging

import com.aandiclub.auth.common.web.v2.V2HeaderValidationWebFilter
import org.springframework.http.server.reactive.ServerHttpRequest
import org.springframework.web.server.ServerWebExchange
import java.time.Instant
import java.util.UUID

data class ApiLogContext(
	val traceId: String,
	val requestId: String,
	val startedAt: Instant,
	val startedAtNanos: Long,
	val method: String,
	val path: String,
	val headers: ApiLogHeaders,
	val client: ApiLogClient,
	val query: Map<String, Any?>,
	var pathVariables: Map<String, Any?> = emptyMap(),
	var requestBody: Any? = emptyMap<String, Any?>(),
	var responseBody: Any? = null,
	var route: String? = null,
	var statusCode: Int? = null,
	var failureReason: String? = null,
	var failureError: ApiLogError? = null,
) {
	fun markRequestBody(body: Any?) {
		requestBody = body ?: emptyMap<String, Any?>()
	}

	fun markResponseBody(body: Any?) {
		responseBody = body
	}

	fun markFailure(reason: String? = null, error: ApiLogError? = null) {
		if (!reason.isNullOrBlank()) {
			failureReason = reason
		}
		if (error != null) {
			failureError = error
		}
	}

	fun latencyMs(): Long = ((System.nanoTime() - startedAtNanos) / 1_000_000).coerceAtLeast(0)

	companion object {
		private val ATTRIBUTE_NAME = ApiLogContext::class.java.name

		fun initialize(exchange: ServerWebExchange): ApiLogContext {
			val request = exchange.request
			val context = ApiLogContext(
				traceId = UUID.randomUUID().toString(),
				requestId = request.headers.getFirst("X-Request-Id")?.trim().takeUnless { it.isNullOrBlank() }
					?: UUID.randomUUID().toString(),
				startedAt = Instant.now(),
				startedAtNanos = System.nanoTime(),
				method = request.method?.name() ?: "UNKNOWN",
				path = request.path.value(),
				headers = request.extractHeaders(),
				client = request.extractClient(),
				query = request.extractQueryParams(),
			)
			exchange.attributes[ATTRIBUTE_NAME] = context
			return context
		}

		fun get(exchange: ServerWebExchange): ApiLogContext? = exchange.getAttribute(ATTRIBUTE_NAME)

		private fun ServerHttpRequest.extractHeaders(): ApiLogHeaders = ApiLogHeaders(
			deviceOS = headers.getFirst(V2HeaderValidationWebFilter.DEVICE_OS_HEADER),
			Authenticate = MaskingUtil.maskAuthenticate(headers.getFirst(V2HeaderValidationWebFilter.AUTHENTICATE_HEADER)),
			timestamp = headers.getFirst(V2HeaderValidationWebFilter.TIMESTAMP_HEADER),
			salt = headers.getFirst(V2HeaderValidationWebFilter.SALT_HEADER),
		)

		private fun ServerHttpRequest.extractClient(): ApiLogClient = ApiLogClient(
			ip = headers.getFirst("X-Forwarded-For")
				?.split(',')
				?.firstOrNull()
				?.trim()
				.takeUnless { it.isNullOrBlank() }
				?: remoteAddress?.address?.hostAddress,
			userAgent = headers.getFirst("User-Agent"),
			appVersion = headers.getFirst("appVersion")
				?: headers.getFirst("App-Version")
				?: headers.getFirst("X-App-Version"),
		)

		private fun ServerHttpRequest.extractQueryParams(): Map<String, Any?> =
			queryParams.entries.associate { (key, values) ->
				key to when {
					values.isEmpty() -> null
					values.size == 1 -> values.first()
					else -> values.toList()
				}
			}
	}
}
