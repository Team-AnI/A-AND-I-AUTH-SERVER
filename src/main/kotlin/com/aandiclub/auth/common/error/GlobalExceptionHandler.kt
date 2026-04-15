package com.aandiclub.auth.common.error

import com.aandiclub.auth.common.api.ApiResponse
import com.aandiclub.auth.common.error.v2.V2ErrorFactory
import com.aandiclub.auth.common.logging.ApiLogContext
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.support.WebExchangeBindException
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.bind.annotation.RestControllerAdvice
import org.springframework.web.server.ServerWebExchange
import org.springframework.web.server.ServerWebInputException

@RestControllerAdvice
class GlobalExceptionHandler(
	private val errorFactory: V2ErrorFactory,
) {

	@ExceptionHandler(AppException::class)
	fun handleAppException(ex: AppException, exchange: ServerWebExchange): ResponseEntity<ApiResponse<Nothing>> {
		ApiLogContext.get(exchange)?.markFailure(
			reason = ex.message,
			error = errorFactory.fromAppException(exchange.request.path.value(), ex).toLogError(),
		)
		val code = ex.errorCode
		return ResponseEntity
			.status(code.status)
			.body(ApiResponse.failure(code.name, ex.message))
	}

	@ExceptionHandler(WebExchangeBindException::class)
	fun handleValidationException(ex: WebExchangeBindException, exchange: ServerWebExchange): ResponseEntity<ApiResponse<Nothing>> {
		val message = ex.bindingResult.fieldErrors.firstOrNull()?.defaultMessage
			?: ErrorCode.INVALID_REQUEST.defaultMessage
		ApiLogContext.get(exchange)?.markFailure(
			reason = message,
			error = errorFactory.validation(exchange.request.path.value(), message, "INVALID_REQUEST").toLogError(),
		)
		return ResponseEntity
			.status(ErrorCode.INVALID_REQUEST.status)
			.body(ApiResponse.failure(ErrorCode.INVALID_REQUEST.name, message))
	}

	@ExceptionHandler(ServerWebInputException::class)
	fun handleInputException(ex: ServerWebInputException, exchange: ServerWebExchange): ResponseEntity<ApiResponse<Nothing>> {
		ApiLogContext.get(exchange)?.markFailure(
			reason = ErrorCode.INVALID_REQUEST.defaultMessage,
			error = errorFactory.validation(
				path = exchange.request.path.value(),
				message = ErrorCode.INVALID_REQUEST.defaultMessage,
				value = "INVALID_REQUEST",
			).toLogError(),
		)
		return ResponseEntity
			.status(ErrorCode.INVALID_REQUEST.status)
			.body(ApiResponse.failure(ErrorCode.INVALID_REQUEST.name, ErrorCode.INVALID_REQUEST.defaultMessage))
	}

	@ExceptionHandler(Exception::class)
	fun handleUnhandledException(ex: Exception, exchange: ServerWebExchange): ResponseEntity<ApiResponse<Nothing>> {
		ApiLogContext.get(exchange)?.markFailure(
			reason = ex.message ?: ErrorCode.INTERNAL_SERVER_ERROR.defaultMessage,
			error = errorFactory.internal(
				path = exchange.request.path.value(),
				message = ErrorCode.INTERNAL_SERVER_ERROR.defaultMessage,
			).toLogError(),
		)
		return ResponseEntity
			.status(ErrorCode.INTERNAL_SERVER_ERROR.status)
			.body(
				ApiResponse.failure(
					ErrorCode.INTERNAL_SERVER_ERROR.name,
					ErrorCode.INTERNAL_SERVER_ERROR.defaultMessage,
				),
			)
	}

	private fun com.aandiclub.auth.common.api.v2.V2ApiError.toLogError() =
		com.aandiclub.auth.common.logging.ApiLogError(
			code = code,
			message = message,
			value = value,
			alert = alert,
		)
}
