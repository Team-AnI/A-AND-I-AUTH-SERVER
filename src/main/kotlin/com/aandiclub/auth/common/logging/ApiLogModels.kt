package com.aandiclub.auth.common.logging

import com.fasterxml.jackson.annotation.JsonProperty
import java.time.Instant

data class ApiLog(
	@get:JsonProperty("@timestamp")
	val `@timestamp`: Instant,
	val level: String,
	val logType: String,
	val message: String,
	val env: String,
	val service: ApiLogService,
	val trace: ApiLogTrace,
	val http: ApiLogHttp,
	val headers: ApiLogHeaders,
	val client: ApiLogClient,
	val actor: ApiLogActor,
	val request: ApiLogRequest,
	val response: ApiLogResponse,
	val tags: List<String>,
)

data class ApiLogService(
	val name: String,
	val domainCode: Int,
	val version: String,
	val instanceId: String,
)

data class ApiLogTrace(
	val traceId: String,
	val requestId: String,
)

data class ApiLogHttp(
	val method: String,
	val path: String,
	val route: String,
	val statusCode: Int,
	val latencyMs: Long,
)

data class ApiLogHeaders(
	val deviceOS: String?,
	@get:JsonProperty("Authenticate")
	val Authenticate: String?,
	val timestamp: String?,
	val salt: String?,
)

data class ApiLogClient(
	val ip: String?,
	val userAgent: String?,
	val appVersion: String?,
)

data class ApiLogActor(
	val userId: String?,
	val role: String?,
	val isAuthenticated: Boolean,
)

data class ApiLogRequest(
	val query: Map<String, Any?>,
	val pathVariables: Map<String, Any?>,
	val body: Any?,
)

data class ApiLogResponse(
	val success: Boolean,
	val data: Any?,
	val error: ApiLogError?,
	val timestamp: Instant,
)

data class ApiLogError(
	val code: Int,
	val message: String,
	val value: String,
	val alert: String,
)
