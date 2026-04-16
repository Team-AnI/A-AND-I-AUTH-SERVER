package com.aandiclub.auth.common.logging

import com.fasterxml.jackson.databind.ObjectMapper
import org.reactivestreams.Publisher
import org.slf4j.LoggerFactory
import org.springframework.core.Ordered
import org.springframework.core.annotation.Order
import org.springframework.core.io.buffer.DataBuffer
import org.springframework.core.io.buffer.DataBufferUtils
import org.springframework.http.MediaType
import org.springframework.http.server.reactive.ServerHttpRequestDecorator
import org.springframework.http.server.reactive.ServerHttpResponseDecorator
import org.springframework.stereotype.Component
import org.springframework.web.reactive.HandlerMapping
import org.springframework.web.server.ServerWebExchange
import org.springframework.web.server.WebFilter
import org.springframework.web.server.WebFilterChain
import reactor.core.publisher.Flux
import reactor.core.publisher.Mono
import java.nio.charset.StandardCharsets
import java.security.Principal

@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
class RequestResponseLoggingFilter(
	private val objectMapper: ObjectMapper,
	private val apiLogFactory: ApiLogFactory,
) : WebFilter {
	private val logger = LoggerFactory.getLogger(API_JSON_LOGGER_NAME)

	override fun filter(exchange: ServerWebExchange, chain: WebFilterChain): Mono<Void> {
		if (!shouldLog(exchange.request.path.value())) {
			return chain.filter(exchange)
		}

		val context = ApiLogContext.initialize(exchange)
		return decorateRequest(exchange, context).flatMap { requestDecoratedExchange ->
			val responseDecorator = BodyCaptureResponseDecorator(requestDecoratedExchange, context, objectMapper)
			val mutatedExchange = requestDecoratedExchange.mutate().response(responseDecorator).build()
			chain.filter(mutatedExchange)
				.then(logAfterCompletion(mutatedExchange, context))
				.onErrorResume { throwable ->
					context.markFailure(reason = throwable.message)
					logAfterCompletion(mutatedExchange, context).then(Mono.error(throwable))
				}
		}
	}

	private fun decorateRequest(exchange: ServerWebExchange, context: ApiLogContext): Mono<ServerWebExchange> {
		val request = exchange.request
		if (!shouldCaptureRequestBody(request.headers.contentType)) {
			context.markRequestBody(
				if (request.headers.contentType?.isCompatibleWith(MediaType.MULTIPART_FORM_DATA) == true) {
					mapOf("contentType" to MediaType.MULTIPART_FORM_DATA_VALUE, "omitted" to "multipart body omitted")
				} else {
					emptyMap<String, Any?>()
				},
			)
			return Mono.just(exchange)
		}

		return DataBufferUtils.join(request.body)
			.defaultIfEmpty(exchange.response.bufferFactory().wrap(ByteArray(0)))
			.map { dataBuffer ->
				val bytes = ByteArray(dataBuffer.readableByteCount())
				dataBuffer.read(bytes)
				DataBufferUtils.release(dataBuffer)
				context.markRequestBody(extractRequestBody(bytes))
				val decoratedRequest = object : ServerHttpRequestDecorator(request) {
					override fun getBody(): Flux<DataBuffer> = Flux.defer {
						Flux.just(exchange.response.bufferFactory().wrap(bytes))
					}
				}
				exchange.mutate().request(decoratedRequest).build()
			}
	}

	private fun extractRequestBody(bytes: ByteArray): Any? {
		if (bytes.isEmpty()) {
			return emptyMap<String, Any?>()
		}
		return parseBody(bytes)
	}

	private fun parseBody(bytes: ByteArray): Any? {
		val rawBody = bytes.toString(StandardCharsets.UTF_8)
		return runCatching {
			MaskingUtil.sanitizePayload(objectMapper.readValue(rawBody, Any::class.java))
		}.getOrElse {
			mapOf("omitted" to "unparseable body omitted")
		}
	}

	private fun logAfterCompletion(exchange: ServerWebExchange, context: ApiLogContext): Mono<Void> {
		context.statusCode = exchange.response.statusCode?.value() ?: context.statusCode ?: 200
		context.route = exchange.getAttribute<String>(HandlerMapping.BEST_MATCHING_PATTERN_ATTRIBUTE) ?: context.path
		context.pathVariables = exchange.getAttribute<Map<String, String>>(HandlerMapping.URI_TEMPLATE_VARIABLES_ATTRIBUTE)
			?.mapValues { (_, value) -> value }
			?: emptyMap()
		return exchange.getPrincipal<Principal>()
			.switchIfEmpty(Mono.just(AnonymousPrincipal))
			.doOnNext { principal ->
				val log = apiLogFactory.create(exchange, context, principal)
				when (log.level) {
					"ERROR" -> logger.error(serialize(log))
					"WARN" -> logger.warn(serialize(log))
					else -> logger.info(serialize(log))
				}
			}
			.then()
	}

	private fun serialize(log: ApiLog): String = runCatching {
		objectMapper.writeValueAsString(log)
	}.getOrElse {
		"""{"@timestamp":"${log.`@timestamp`}","level":"ERROR","logType":"API_ERROR","message":"Failed to serialize API log","env":"${log.env}","service":{"name":"${log.service.name}","domainCode":${log.service.domainCode},"version":"${log.service.version}","instanceId":"${log.service.instanceId}"},"trace":{"traceId":"${log.trace.traceId}","requestId":"${log.trace.requestId}"},"http":{"method":"${log.http.method}","path":"${log.http.path}","route":"${log.http.route}","statusCode":${log.http.statusCode},"latencyMs":${log.http.latencyMs}},"headers":${objectMapper.writeValueAsString(log.headers)},"client":${objectMapper.writeValueAsString(log.client)},"actor":${objectMapper.writeValueAsString(log.actor)},"request":${objectMapper.writeValueAsString(log.request)},"response":${objectMapper.writeValueAsString(log.response)},"tags":${objectMapper.writeValueAsString(log.tags)}}"""
	}

	private fun shouldCaptureRequestBody(contentType: MediaType?): Boolean = when {
		contentType == null -> true
		contentType.isCompatibleWith(MediaType.APPLICATION_JSON) -> true
		contentType.isCompatibleWith(MediaType.APPLICATION_FORM_URLENCODED) -> true
		contentType.type == "text" -> true
		else -> false
	}

	private fun shouldLog(path: String): Boolean =
		path == "/activate" ||
			path == "/v2" || path.startsWith("/v2/") ||
			path == "/v1" || path.startsWith("/v1/") ||
			path == "/api" || path.startsWith("/api/") ||
			path == "/actuator" || path.startsWith("/actuator/")

	private class BodyCaptureResponseDecorator(
		exchange: ServerWebExchange,
		private val context: ApiLogContext,
		private val objectMapper: ObjectMapper,
	) : ServerHttpResponseDecorator(exchange.response) {
		override fun writeWith(body: Publisher<out DataBuffer>): Mono<Void> =
			super.writeWith(Flux.from(body).map { dataBuffer ->
				val bytes = ByteArray(dataBuffer.readableByteCount())
				dataBuffer.read(bytes)
				DataBufferUtils.release(dataBuffer)
				capture(bytes)
				bufferFactory().wrap(bytes)
			})

		override fun writeAndFlushWith(body: Publisher<out Publisher<out DataBuffer>>): Mono<Void> =
			super.writeAndFlushWith(
				Flux.from(body).map { publisher ->
					Flux.from(publisher).map { dataBuffer ->
						val bytes = ByteArray(dataBuffer.readableByteCount())
						dataBuffer.read(bytes)
						DataBufferUtils.release(dataBuffer)
						capture(bytes)
						bufferFactory().wrap(bytes)
					}
				},
			)

		private fun capture(bytes: ByteArray) {
			if (bytes.isEmpty()) {
				return
			}
			val rawBody = bytes.toString(StandardCharsets.UTF_8)
			val parsed = runCatching {
				MaskingUtil.sanitizePayload(objectMapper.readValue(rawBody, Any::class.java))
			}.getOrElse {
				mapOf("omitted" to "unparseable body omitted")
			}
			context.markResponseBody(parsed)
		}
	}

	private object AnonymousPrincipal : Principal {
		override fun getName(): String = "anonymous"
	}

	companion object {
		const val API_JSON_LOGGER_NAME = "API_JSON"
	}
}
