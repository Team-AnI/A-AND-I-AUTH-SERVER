package com.aandiclub.auth.auth.web.v2

import com.aandiclub.auth.auth.service.AuthService
import com.aandiclub.auth.auth.web.dto.ActivateRequest
import com.aandiclub.auth.auth.web.dto.LoginRequest
import com.aandiclub.auth.auth.web.dto.LoginResponse
import com.aandiclub.auth.auth.web.dto.LogoutRequest
import com.aandiclub.auth.auth.web.dto.RefreshRequest
import com.aandiclub.auth.auth.web.dto.v2.V2ActivateRequest
import com.aandiclub.auth.auth.web.dto.v2.V2ActivateResponse
import com.aandiclub.auth.auth.web.dto.v2.V2LoginRequest
import com.aandiclub.auth.auth.web.dto.v2.V2LoginResponse
import com.aandiclub.auth.auth.web.dto.v2.V2LoginUser
import com.aandiclub.auth.auth.web.dto.v2.V2LogoutRequest
import com.aandiclub.auth.auth.web.dto.v2.V2LogoutResponse
import com.aandiclub.auth.auth.web.dto.v2.V2RefreshRequest
import com.aandiclub.auth.auth.web.dto.v2.V2RefreshResponse
import com.aandiclub.auth.common.api.v2.V2ApiResponse
import jakarta.validation.Valid
import org.springframework.validation.annotation.Validated
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import reactor.core.publisher.Mono

@RestController
@RequestMapping("/v2/auth")
@Validated
class V2AuthController(
	private val authService: AuthService,
) {
	@PostMapping("/login")
	fun login(@Valid @RequestBody request: V2LoginRequest): Mono<V2ApiResponse<V2LoginResponse>> =
		authService.login(LoginRequest(username = request.username, password = request.password))
			.map { V2ApiResponse.success(it.toV2()) }

	@PostMapping("/refresh")
	fun refresh(@Valid @RequestBody request: V2RefreshRequest): Mono<V2ApiResponse<V2RefreshResponse>> =
		authService.refresh(RefreshRequest(refreshToken = request.refreshToken))
			.map { V2ApiResponse.success(V2RefreshResponse(accessToken = it.accessToken, expiresIn = it.expiresIn)) }

	@PostMapping("/logout")
	fun logout(@Valid @RequestBody request: V2LogoutRequest): Mono<V2ApiResponse<V2LogoutResponse>> =
		authService.logout(LogoutRequest(refreshToken = request.refreshToken))
			.map { V2ApiResponse.success(V2LogoutResponse(loggedOut = it.success)) }

	private fun LoginResponse.toV2(): V2LoginResponse =
		V2LoginResponse(
			accessToken = accessToken,
			refreshToken = refreshToken,
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
