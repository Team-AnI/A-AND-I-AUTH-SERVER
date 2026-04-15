package com.aandiclub.auth.security.web

import com.aandiclub.auth.common.error.v2.V2ErrorFactory
import com.aandiclub.auth.common.error.v2.V2ErrorResponseWriter
import com.aandiclub.auth.common.logging.ApiLogContext
import com.aandiclub.auth.common.logging.ApiLogError
import com.aandiclub.auth.common.web.v2.V2ApiPaths
import org.springframework.http.HttpStatus
import org.springframework.security.access.AccessDeniedException
import org.springframework.security.web.server.authorization.HttpStatusServerAccessDeniedHandler
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler
import org.springframework.stereotype.Component
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono

@Component
class V2AwareServerAccessDeniedHandler(
	private val errorFactory: V2ErrorFactory,
	private val responseWriter: V2ErrorResponseWriter,
) : ServerAccessDeniedHandler {
	private val fallback = HttpStatusServerAccessDeniedHandler(HttpStatus.FORBIDDEN)

	override fun handle(exchange: ServerWebExchange, denied: AccessDeniedException): Mono<Void> {
		val path = exchange.request.path.value()
		if (!V2ApiPaths.isV2(path)) {
			return fallback.handle(exchange, denied)
		}

		val error = errorFactory.forbidden(
			path = path,
			message = "You do not have permission to access this resource.",
			value = "FORBIDDEN",
			detail = 1,
		)
		ApiLogContext.get(exchange)?.markFailure(
			reason = error.message,
			error = ApiLogError(code = error.code, message = error.message, value = error.value, alert = error.alert),
		)
		return responseWriter.write(
			response = exchange.response,
			status = HttpStatus.FORBIDDEN,
			error = error,
		)
	}
}
