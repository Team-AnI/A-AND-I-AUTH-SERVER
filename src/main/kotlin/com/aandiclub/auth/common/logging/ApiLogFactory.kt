package com.aandiclub.auth.common.logging

import com.aandiclub.auth.common.error.v2.V2ErrorFactory
import com.aandiclub.auth.security.auth.AuthenticatedUser
import org.springframework.core.env.Environment
import org.springframework.security.core.Authentication
import org.springframework.stereotype.Component
import org.springframework.web.reactive.HandlerMapping
import org.springframework.web.server.ServerWebExchange
import java.security.Principal
import java.time.Instant
import java.util.UUID

@Component
class ApiLogFactory(
	private val environment: Environment,
	private val errorFactory: V2ErrorFactory,
) {
	private val serviceName = environment.getProperty("spring.application.name") ?: "auth"
	private val envName = environment.activeProfiles.firstOrNull()
		?: environment.getProperty("app.env")
		?: "default"
	private val serviceVersion = environment.getProperty("app.version")
		?: environment.getProperty("APP_VERSION")
		?: javaClass.`package`?.implementationVersion
		?: "0.0.1-SNAPSHOT"
	private val instanceId = environment.getProperty("spring.application.instance-id")
		?: environment.getProperty("HOSTNAME")
		?: UUID.randomUUID().toString()

	fun create(exchange: ServerWebExchange, context: ApiLogContext, principal: Principal?): ApiLog {
		val pathVariables = context.pathVariables.ifEmpty {
			resolvePathVariables(exchange)
		}
		val route = resolveRoute(
			path = context.path,
			route = context.route ?: exchange.getAttribute(HandlerMapping.BEST_MATCHING_PATTERN_ATTRIBUTE),
			pathVariables = pathVariables,
		)
		val response = normalizeResponse(route = route, path = context.path, statusCode = context.statusCode ?: 200, context = context)
		val success = response.success
		val statusCode = context.statusCode ?: exchange.response.statusCode?.value() ?: if (success) 200 else 500
		val level = if (success) {
			"INFO"
		} else if (statusCode >= 500) {
			"ERROR"
		} else {
			"WARN"
		}
		val message = if (success) {
			"HTTP request completed"
		} else {
			buildFailureMessage(route, context.failureReason, response.error?.message)
		}

		return ApiLog(
			`@timestamp` = Instant.now(),
			level = level,
			logType = if (success) "API" else "API_ERROR",
			message = message,
			env = envName,
			service = ApiLogService(
				name = serviceName,
				domainCode = 2,
				version = serviceVersion,
				instanceId = instanceId,
			),
			trace = ApiLogTrace(
				traceId = context.traceId,
				requestId = context.requestId,
			),
			http = ApiLogHttp(
				method = context.method,
				path = context.path,
				route = route,
				statusCode = statusCode,
				latencyMs = context.latencyMs(),
			),
			headers = context.headers,
			client = context.client,
			actor = resolveActor(principal),
			request = ApiLogRequest(
				query = context.query,
				pathVariables = pathVariables,
				body = context.requestBody ?: emptyMap<String, Any?>(),
			),
			response = response,
			tags = buildTags(route, success),
		)
	}

	fun toLogError(path: String, statusCode: Int, message: String, value: String = "REQUEST_FAILED"): ApiLogError =
		when (statusCode) {
			400 -> errorFactory.validation(path, message, value)
			401 -> errorFactory.unauthorized(path, message, value)
			403 -> errorFactory.forbidden(path, message, value)
			404 -> errorFactory.notFound(path, message, value)
			else -> errorFactory.internal(path, message, value)
		}.toLogError()

	private fun normalizeResponse(route: String, path: String, statusCode: Int, context: ApiLogContext): ApiLogResponse {
		val captured = context.responseBody as? Map<*, *>
		val success = when (val responseSuccess = captured?.get("success")) {
			is Boolean -> responseSuccess && statusCode < 400
			else -> statusCode < 400 && context.failureError == null
		}
		val timestamp = parseTimestamp(captured?.get("timestamp")) ?: Instant.now()
		val data = if (success) {
			MaskingUtil.sanitizePayload(captured?.get("data"))
		} else {
			null
		}
		val error = when {
			success -> null
			context.failureError != null -> context.failureError
			captured?.get("error") is Map<*, *> -> normalizeError(path, statusCode, captured.get("error") as Map<*, *>)
			else -> toLogError(path, statusCode, context.failureReason ?: "Request failed.")
		}
		return ApiLogResponse(
			success = success,
			data = data,
			error = error,
			timestamp = timestamp,
		)
	}

	private fun normalizeError(path: String, statusCode: Int, rawError: Map<*, *>): ApiLogError {
		val code = when (val rawCode = rawError["code"]) {
			is Number -> rawCode.toInt()
			is String -> rawCode.toIntOrNull()
			else -> null
		}
		val message = rawError["message"]?.toString() ?: "Request failed."
		val value = rawError["value"]?.toString() ?: "REQUEST_FAILED"
		val alert = rawError["alert"]?.toString() ?: message
		return if (code != null) {
			ApiLogError(code = code, message = message, value = value, alert = alert)
		} else {
			toLogError(path = path, statusCode = statusCode, message = message, value = value)
		}
	}

	private fun parseTimestamp(value: Any?): Instant? = when (value) {
		is Instant -> value
		is String -> runCatching { Instant.parse(value) }.getOrNull()
		else -> null
	}

	@Suppress("UNCHECKED_CAST")
	private fun resolvePathVariables(exchange: ServerWebExchange): Map<String, Any?> =
		(exchange.getAttribute<Map<String, String>>(HandlerMapping.URI_TEMPLATE_VARIABLES_ATTRIBUTE) ?: emptyMap())
			.mapValues { (_, value) -> value }

	private fun resolveActor(principal: Principal?): ApiLogActor {
		if (principal !is Authentication || !principal.isAuthenticated) {
			return ApiLogActor(userId = null, role = null, isAuthenticated = false)
		}
		val authenticatedUser = principal.principal as? AuthenticatedUser
		return if (authenticatedUser == null) {
			ApiLogActor(userId = null, role = null, isAuthenticated = false)
		} else {
			ApiLogActor(
				userId = authenticatedUser.userId.toString(),
				role = authenticatedUser.role.name,
				isAuthenticated = true,
			)
		}
	}

	private fun buildFailureMessage(route: String, reason: String?, errorMessage: String?): String {
		val explicit = MaskingUtil.sanitizeMessage(reason)
		if (!explicit.isNullOrBlank() && explicit.contains("failed", ignoreCase = true)) {
			return explicit
		}
		val detail = explicit ?: MaskingUtil.sanitizeMessage(errorMessage) ?: "Request processing failed."
		val segments = route.trim('/').split('/').filter { it.isNotBlank() }
		val action = segments.lastOrNull().takeUnless { it?.startsWith('{') == true }
			?: segments.dropLast(1).lastOrNull()
		val label = when (action) {
			"login" -> "Login"
			"refresh" -> "Token refresh"
			"logout" -> "Logout"
			"activate" -> "Activation"
			"lookup" -> "User lookup"
			"password" -> "Password change"
			"upload-url" -> "Profile image upload URL issuance"
			"me" -> "User profile retrieval"
			else -> "Request"
		}
		return "$label failed: $detail"
	}

	private fun resolveRoute(path: String, route: String?, pathVariables: Map<String, Any?>): String {
		if (!route.isNullOrBlank() && route != path) {
			return route
		}
		var resolved = route ?: path
		pathVariables.forEach { (key, value) ->
			val token = value?.toString() ?: return@forEach
			resolved = resolved.replace("/$token", "/{$key}")
		}
		return resolved
	}

	private fun buildTags(route: String, success: Boolean): List<String> {
		val segments = route.trim('/').split('/').filter { it.isNotBlank() }
		val normalizedSegments = if (segments.firstOrNull()?.matches(Regex("v\\d+")) == true) {
			segments.drop(1)
		} else {
			segments
		}
		val feature = normalizedSegments.firstOrNull() ?: "root"
		val detail = normalizedSegments.lastOrNull() ?: feature
		return listOf(serviceName, feature, if (success) "success" else "fail", detail)
	}

	private fun com.aandiclub.auth.common.api.v2.V2ApiError.toLogError(): ApiLogError = ApiLogError(
		code = code,
		message = message,
		value = value,
		alert = alert,
	)
}
