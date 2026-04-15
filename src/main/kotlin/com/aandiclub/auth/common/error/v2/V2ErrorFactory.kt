package com.aandiclub.auth.common.error.v2

import com.aandiclub.auth.common.api.v2.V2ApiError
import com.aandiclub.auth.common.error.AppException
import com.aandiclub.auth.common.error.ErrorCode
import com.aandiclub.auth.common.web.v2.V2ApiPaths
import org.springframework.stereotype.Component

@Component
class V2ErrorFactory {

	fun fromAppException(path: String, ex: AppException): V2ApiError {
		val spec = when (ex.errorCode) {
			ErrorCode.INVALID_REQUEST -> V2ErrorSpec(V2ErrorCategory.VALIDATION, 1, ex.value, ex.message, ex.alert)
			ErrorCode.UNAUTHORIZED -> V2ErrorSpec(V2ErrorCategory.AUTHENTICATION, 1, ex.value, ex.message, ex.alert)
			ErrorCode.FORBIDDEN -> V2ErrorSpec(V2ErrorCategory.AUTHORIZATION, 1, ex.value, ex.message, ex.alert)
			ErrorCode.NOT_FOUND -> V2ErrorSpec(V2ErrorCategory.NOT_FOUND, 1, ex.value, ex.message, ex.alert)
			ErrorCode.INTERNAL_SERVER_ERROR -> V2ErrorSpec(V2ErrorCategory.INTERNAL, 1, ex.value, ex.message, ex.alert)
		}
		return spec.toApiError(resolveService(path))
	}

	fun validation(path: String, message: String, value: String, detail: Int = 1, alert: String = message): V2ApiError =
		V2ErrorSpec(V2ErrorCategory.VALIDATION, detail, value, message, alert).toApiError(resolveService(path))

	fun unauthorized(path: String, message: String, value: String = "UNAUTHORIZED", detail: Int = 1): V2ApiError =
		V2ErrorSpec(V2ErrorCategory.AUTHENTICATION, detail, value, message, message).toApiError(resolveService(path))

	fun forbidden(path: String, message: String, value: String = "FORBIDDEN", detail: Int = 1): V2ApiError =
		V2ErrorSpec(V2ErrorCategory.AUTHORIZATION, detail, value, message, message).toApiError(resolveService(path))

	fun internal(path: String, message: String, value: String = "INTERNAL_SERVER_ERROR", detail: Int = 1): V2ApiError =
		V2ErrorSpec(V2ErrorCategory.INTERNAL, detail, value, message, message).toApiError(resolveService(path))

	private fun resolveService(path: String): V2ServiceCode = when {
		path.startsWith("/v2/me") || path.startsWith("/v2/users") -> V2ServiceCode.USER
		path.startsWith("/v2/admin/users") -> V2ServiceCode.USER
		path.startsWith("/v2/ping") -> V2ServiceCode.COMMON
		V2ApiPaths.isV2(path) -> V2ServiceCode.AUTH
		else -> V2ServiceCode.COMMON
	}

	private data class V2ErrorSpec(
		val category: V2ErrorCategory,
		val detail: Int,
		val value: String,
		val message: String,
		val alert: String,
	) {
		fun toApiError(service: V2ServiceCode): V2ApiError =
			V2ApiError(
				code = service.digit * 10000 + category.digit * 1000 + detail,
				message = message,
				value = value,
				alert = alert,
			)
	}

	private enum class V2ServiceCode(val digit: Int) {
		GATEWAY(1),
		AUTH(2),
		USER(3),
		REPORT(4),
		JUDGE(5),
		BLOG(6),
		COMMON(9),
	}

	private enum class V2ErrorCategory(val digit: Int) {
		GENERAL(0),
		AUTHENTICATION(1),
		AUTHORIZATION(2),
		VALIDATION(3),
		BUSINESS(4),
		NOT_FOUND(5),
		CONFLICT(6),
		EXTERNAL(7),
		INTERNAL(8),
	}
}
