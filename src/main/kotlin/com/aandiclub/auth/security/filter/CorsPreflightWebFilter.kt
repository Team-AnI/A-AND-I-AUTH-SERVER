package com.aandiclub.auth.security.filter

import com.aandiclub.auth.common.api.ApiResponse
import com.aandiclub.auth.common.api.v2.V2ApiResponse
import com.aandiclub.auth.common.error.ErrorMessageLocalizer
import com.aandiclub.auth.common.error.v2.V2ErrorFactory
import com.aandiclub.auth.common.web.v2.V2ApiPaths
import com.fasterxml.jackson.databind.ObjectMapper
import com.aandiclub.auth.security.config.AppCorsProperties
import org.springframework.core.Ordered
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpMethod
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.stereotype.Component
import org.springframework.web.server.ServerWebExchange
import org.springframework.web.server.WebFilter
import org.springframework.web.server.WebFilterChain
import reactor.core.publisher.Mono

@Component
class CorsPreflightWebFilter(
	private val corsProperties: AppCorsProperties,
	private val objectMapper: ObjectMapper,
	private val errorFactory: V2ErrorFactory,
) : WebFilter, Ordered {
	override fun getOrder(): Int = Ordered.HIGHEST_PRECEDENCE

	override fun filter(exchange: ServerWebExchange, chain: WebFilterChain): Mono<Void> {
		val request = exchange.request
		val origin = request.headers.origin ?: return chain.filter(exchange)

		val allowedOrigins = corsProperties.allowedOriginsList()
		if (!allowedOrigins.contains(origin)) {
			return writeCorsError(
				exchange = exchange,
				status = HttpStatus.FORBIDDEN,
				message = "Origin is not allowed.",
				value = "CORS_ORIGIN_NOT_ALLOWED",
				detail = 4,
			)
		}

		if (request.method != HttpMethod.OPTIONS) {
			return chain.filter(exchange)
		}

		val requestedMethod = request.headers.getFirst(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD)?.uppercase()
			?: return writeCorsError(
				exchange = exchange,
				status = HttpStatus.BAD_REQUEST,
				message = "Invalid request.",
				value = "CORS_METHOD_REQUIRED",
				detail = 5,
			)

		val allowedMethods = corsProperties.allowedMethodsList().map { it.uppercase() }
		if (!allowedMethods.contains(requestedMethod)) {
			return writeCorsError(
				exchange = exchange,
				status = HttpStatus.FORBIDDEN,
				message = "Requested CORS method is not allowed.",
				value = "CORS_METHOD_NOT_ALLOWED",
				detail = 6,
			)
		}

		val requestedHeaders = request.headers.getFirst(HttpHeaders.ACCESS_CONTROL_REQUEST_HEADERS)
			?.split(",")
			?.map { it.trim() }
			?.filter { it.isNotBlank() }
			.orEmpty()
		val allowedHeaders = corsProperties.allowedHeadersList()
		val allowedHeaderSet = allowedHeaders.map { it.lowercase() }.toSet()
		if (requestedHeaders.any { it.lowercase() !in allowedHeaderSet }) {
			return writeCorsError(
				exchange = exchange,
				status = HttpStatus.FORBIDDEN,
				message = "Requested CORS headers are not allowed.",
				value = "CORS_HEADER_NOT_ALLOWED",
				detail = 7,
			)
		}

		val responseHeaders = exchange.response.headers
		responseHeaders.add(HttpHeaders.VARY, "Origin")
		responseHeaders.add(HttpHeaders.VARY, "Access-Control-Request-Method")
		responseHeaders.add(HttpHeaders.VARY, "Access-Control-Request-Headers")
		responseHeaders.accessControlAllowOrigin = origin
		responseHeaders.add(HttpHeaders.ACCESS_CONTROL_ALLOW_METHODS, allowedMethods.joinToString(","))
		responseHeaders.add(
			HttpHeaders.ACCESS_CONTROL_ALLOW_HEADERS,
			allowedHeaders.joinToString(","),
		)
		if (corsProperties.allowCredentials) {
			responseHeaders.accessControlAllowCredentials = true
		}
		responseHeaders.accessControlMaxAge = corsProperties.maxAgeSeconds

		exchange.response.statusCode = HttpStatus.OK
		return exchange.response.setComplete()
	}

	private fun writeCorsError(
		exchange: ServerWebExchange,
		status: HttpStatus,
		message: String,
		value: String,
		detail: Int,
	): Mono<Void> {
		if (exchange.response.isCommitted) {
			return exchange.response.setComplete()
		}

		exchange.response.statusCode = status
		exchange.response.headers.contentType = MediaType.APPLICATION_JSON
		val payload = if (V2ApiPaths.isV2(exchange.request.path.value())) {
			V2ApiResponse.failure(
				errorFactory.validation(
					path = exchange.request.path.value(),
					message = message,
					value = value,
					detail = detail,
				),
			)
		} else {
			ApiResponse.failure("FORBIDDEN", ErrorMessageLocalizer.localize(message))
		}
		val body = objectMapper.writeValueAsBytes(payload)
		return exchange.response.writeWith(Mono.just(exchange.response.bufferFactory().wrap(body)))
	}
}
