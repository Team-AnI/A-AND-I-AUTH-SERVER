package com.aandiclub.auth.auth.web.v2

import com.aandiclub.auth.auth.service.AuthService
import com.aandiclub.auth.auth.web.dto.ActivateRequest
import com.aandiclub.auth.auth.web.dto.LoginRequest
import com.aandiclub.auth.auth.web.dto.LoginResponse
import com.aandiclub.auth.auth.web.dto.LogoutRequest
import com.aandiclub.auth.auth.web.dto.RefreshRequest
import com.aandiclub.auth.auth.web.dto.v2.*
import com.aandiclub.auth.common.api.v2.V2ApiResponse
import com.aandiclub.auth.common.error.AppException
import com.aandiclub.auth.common.error.ErrorCode
import com.aandiclub.auth.common.web.v2.V2HeaderValidationWebFilter
import com.aandiclub.auth.security.jwt.JwtProperties
import com.aandiclub.auth.security.service.JwtService
import jakarta.validation.Valid
import org.springframework.http.ResponseCookie
import org.springframework.validation.annotation.Validated
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono
import java.time.Duration

@RestController
@RequestMapping("/v2/auth")
@Validated
class V2AuthController(
	private val authService: AuthService,
	private val jwtService: JwtService,
	private val jwtProperties: JwtProperties,
) {
	@PostMapping("/login")
	fun login(
		@Valid @RequestBody request: V2LoginRequest,
		exchange: ServerWebExchange,
	): Mono<V2ApiResponse<V2LoginResponse>> {
		val isWeb = isWebClient(exchange)
		return authService.login(LoginRequest(username = request.username, password = request.password))
			.map { response ->
				val refreshToken = handleRefreshToken(exchange, response.refreshToken, isWeb)
				V2ApiResponse.success(response.toV2(refreshToken))
			}
	}

	@PostMapping("/refresh")
	fun refresh(
		@Valid @RequestBody request: V2RefreshRequest,
		exchange: ServerWebExchange,
	): Mono<V2ApiResponse<V2RefreshResponse>> {
		val refreshToken = request.refreshToken
			?: exchange.request.cookies.getFirst(REFRESH_TOKEN_COOKIE)?.value
			?: throw AppException(ErrorCode.UNAUTHORIZED, "Refresh token is missing.")

		return authService.refresh(RefreshRequest(refreshToken = refreshToken))
			.map { V2ApiResponse.success(V2RefreshResponse(accessToken = it.accessToken, expiresIn = it.expiresIn)) }
	}

	@PostMapping("/logout")
	fun logout(
		@Valid @RequestBody request: V2LogoutRequest,
		exchange: ServerWebExchange,
	): Mono<V2ApiResponse<V2LogoutResponse>> {
		val isWeb = isWebClient(exchange)
		val refreshToken = request.refreshToken
			?: exchange.request.cookies.getFirst(REFRESH_TOKEN_COOKIE)?.value
			?: return Mono.just(V2ApiResponse.success(V2LogoutResponse(loggedOut = true)))

		return authService.logout(LogoutRequest(refreshToken = refreshToken))
			.doOnSuccess { if (isWeb) clearRefreshTokenCookie(exchange) }
			.map { V2ApiResponse.success(V2LogoutResponse(loggedOut = it.success)) }
	}

	private fun isWebClient(exchange: ServerWebExchange): Boolean =
		exchange.request.headers.getFirst(V2HeaderValidationWebFilter.DEVICE_OS_HEADER)
			?.equals("WEB", ignoreCase = true) == true

	private fun handleRefreshToken(
		exchange: ServerWebExchange,
		refreshToken: String,
		isWeb: Boolean,
	): String? {
		if (isWeb) {
			val cookie = ResponseCookie.from(REFRESH_TOKEN_COOKIE, refreshToken)
				.httpOnly(true)
				.secure(true)
				.path("/")
				.maxAge(Duration.ofSeconds(jwtProperties.refreshTokenExpSeconds))
				.sameSite("Strict")
				.build()
			exchange.response.addCookie(cookie)
			return null
		}
		return refreshToken
	}

	private fun clearRefreshTokenCookie(exchange: ServerWebExchange) {
		val cookie = ResponseCookie.from(REFRESH_TOKEN_COOKIE, "")
			.httpOnly(true)
			.secure(true)
			.path("/")
			.maxAge(0)
			.sameSite("Strict")
			.build()
		exchange.response.addCookie(cookie)
	}

	private fun LoginResponse.toV2(v2RefreshToken: String?): V2LoginResponse =
		V2LoginResponse(
			accessToken = accessToken,
			refreshToken = v2RefreshToken,
			expiresIn = expiresIn,
			tokenType = tokenType,
			forcePasswordChange = forcePasswordChange,
			user = V2LoginUser(
				id = user.id,
				username = user.username,
				role = user.role,
				publicCode = user.publicCode,
			),
		)

	companion object {
		private const val REFRESH_TOKEN_COOKIE = "refresh_token"
	}
}

@RestController
@RequestMapping("/v2")
@Validated
class V2ActivationController(
	private val authService: AuthService,
) {
	@PostMapping("/activate")
	fun activate(@Valid @RequestBody request: V2ActivateRequest): Mono<V2ApiResponse<V2ActivateResponse>> =
		authService.activate(
			ActivateRequest(
				token = request.token,
				password = request.password,
				username = request.username,
			),
		).map { V2ApiResponse.success(V2ActivateResponse(activated = it.success)) }
}
