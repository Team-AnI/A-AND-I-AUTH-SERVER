package com.aandiclub.auth.common.error.v2

import com.aandiclub.auth.common.api.v2.V2ApiError
import com.aandiclub.auth.common.api.v2.V2ApiResponse
import com.fasterxml.jackson.databind.ObjectMapper
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.http.server.reactive.ServerHttpResponse
import org.springframework.stereotype.Component
import reactor.core.publisher.Mono

@Component
class V2ErrorResponseWriter(
	private val objectMapper: ObjectMapper,
) {
	fun write(response: ServerHttpResponse, status: HttpStatus, error: V2ApiError): Mono<Void> {
		if (response.isCommitted) {
			return response.setComplete()
		}
		response.statusCode = status
		response.headers.contentType = MediaType.APPLICATION_JSON
		val body = objectMapper.writeValueAsBytes(V2ApiResponse.failure(error))
		return response.writeWith(Mono.just(response.bufferFactory().wrap(body)))
	}
}
