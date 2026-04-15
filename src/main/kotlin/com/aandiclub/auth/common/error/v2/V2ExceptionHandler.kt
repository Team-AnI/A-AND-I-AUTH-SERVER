package com.aandiclub.auth.common.error.v2

import com.aandiclub.auth.admin.web.v2.V2AdminController
import com.aandiclub.auth.auth.web.v2.V2ActivationController
import com.aandiclub.auth.auth.web.v2.V2AuthController
import com.aandiclub.auth.common.api.v2.V2ApiResponse
import com.aandiclub.auth.common.error.AppException
import com.aandiclub.auth.common.error.ErrorCode
import com.aandiclub.auth.common.logging.ApiLogContext
import com.aandiclub.auth.common.logging.ApiLogError
import com.aandiclub.auth.common.web.v2.V2PingController
import com.aandiclub.auth.user.web.v2.V2UserController
import com.aandiclub.auth.user.web.v2.V2UserLookupController
import org.springframework.core.Ordered
import org.springframework.core.annotation.Order
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.bind.annotation.RestControllerAdvice
import org.springframework.web.bind.support.WebExchangeBindException
import org.springframework.web.server.ServerWebExchange
import org.springframework.web.server.ServerWebInputException

@RestControllerAdvice(
	assignableTypes = [
		V2AuthController::class,
		V2ActivationController::class,
		V2UserController::class,
		V2UserLookupController::class,
		V2AdminController::class,
		V2PingController::class,
	],
)
@Order(Ordered.HIGHEST_PRECEDENCE)
class V2ExceptionHandler(
	private val errorFactory: V2ErrorFactory,
) {

	@ExceptionHandler(AppException::class)
	fun handleAppException(ex: AppException, exchange: ServerWebExchange): ResponseEntity<V2ApiResponse<Nothing>> {
		val error = errorFactory.fromAppException(exchange.request.path.value(), ex)
		ApiLogContext.get(exchange)?.markFailure(reason = ex.message, error = error.toLogError())
		return ResponseEntity
			.status(ex.errorCode.status)
			.body(V2ApiResponse.failure(error))
	}

	@ExceptionHandler(WebExchangeBindException::class)
	fun handleValidationException(
		ex: WebExchangeBindException,
		exchange: ServerWebExchange,
	): ResponseEntity<V2ApiResponse<Nothing>> {
		val message = ex.bindingResult.fieldErrors.firstOrNull()?.defaultMessage
			?: ErrorCode.INVALID_REQUEST.defaultMessage
		val error = errorFactory.validation(
			path = exchange.request.path.value(),
			message = message,
			value = "INVALID_REQUEST",
		)
		ApiLogContext.get(exchange)?.markFailure(reason = message, error = error.toLogError())
		return ResponseEntity
			.status(ErrorCode.INVALID_REQUEST.status)
			.body(V2ApiResponse.failure(error))
	}

	@ExceptionHandler(ServerWebInputException::class)
	fun handleInputException(
		ex: ServerWebInputException,
		exchange: ServerWebExchange,
	): ResponseEntity<V2ApiResponse<Nothing>> {
		val error = errorFactory.validation(
			path = exchange.request.path.value(),
			message = ErrorCode.INVALID_REQUEST.defaultMessage,
			value = "INVALID_REQUEST",
		)
		ApiLogContext.get(exchange)?.markFailure(reason = ErrorCode.INVALID_REQUEST.defaultMessage, error = error.toLogError())
		return ResponseEntity
			.status(ErrorCode.INVALID_REQUEST.status)
			.body(V2ApiResponse.failure(error))
	}

	@ExceptionHandler(Exception::class)
	fun handleUnhandledException(
		ex: Exception,
		exchange: ServerWebExchange,
	): ResponseEntity<V2ApiResponse<Nothing>> {
		val error = errorFactory.internal(
			path = exchange.request.path.value(),
			message = ErrorCode.INTERNAL_SERVER_ERROR.defaultMessage,
		)
		ApiLogContext.get(exchange)?.markFailure(
			reason = ex.message ?: ErrorCode.INTERNAL_SERVER_ERROR.defaultMessage,
			error = error.toLogError(),
		)
		return ResponseEntity
			.status(ErrorCode.INTERNAL_SERVER_ERROR.status)
			.body(V2ApiResponse.failure(error))
	}

	private fun com.aandiclub.auth.common.api.v2.V2ApiError.toLogError() = ApiLogError(
		code = code,
		message = message,
		value = value,
		alert = alert,
	)
}
