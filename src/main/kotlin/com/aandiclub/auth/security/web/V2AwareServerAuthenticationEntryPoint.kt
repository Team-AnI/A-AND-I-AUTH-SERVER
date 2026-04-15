package com.aandiclub.auth.security.web

import com.aandiclub.auth.common.error.v2.V2ErrorFactory
import com.aandiclub.auth.common.error.v2.V2ErrorResponseWriter
import com.aandiclub.auth.common.logging.ApiLogContext
import com.aandiclub.auth.common.logging.ApiLogError
import com.aandiclub.auth.common.web.v2.V2ApiPaths
import org.springframework.http.HttpStatus
import org.springframework.security.core.AuthenticationException
import org.springframework.security.web.server.ServerAuthenticationEntryPoint
import org.springframework.security.web.server.authentication.HttpStatusServerEntryPoint
import org.springframework.stereotype.Component
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono

@Component
class V2AwareServerAuthenticationEntryPoint(
	private val errorFactory: V2ErrorFactory,
	private val responseWriter: V2ErrorResponseWriter,
) : ServerAuthenticationEntryPoint {
	private val fallback = HttpStatusServerEntryPoint(HttpStatus.UNAUTHORIZED)

	override fun commence(exchange: ServerWebExchange, ex: AuthenticationException): Mono<Void> {
		val path = exchange.request.path.value()
		if (!V2ApiPaths.isV2(path)) {
			return fallback.commence(exchange, ex)
		}

		val error = errorFactory.unauthorized(
			path = path,
			message = "Authentication is required.",
			value = "UNAUTHORIZED",
			detail = 1,
		)
		ApiLogContext.get(exchange)?.markFailure(
			reason = error.message,
			error = ApiLogError(code = error.code, message = error.message, value = error.value, alert = error.alert),
		)
		return responseWriter.write(
			response = exchange.response,
			status = HttpStatus.UNAUTHORIZED,
			error = error,
		)
	}
}
