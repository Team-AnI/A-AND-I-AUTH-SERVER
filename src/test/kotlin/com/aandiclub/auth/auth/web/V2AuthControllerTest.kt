package com.aandiclub.auth.auth.web

import com.aandiclub.auth.auth.service.AuthService
import com.aandiclub.auth.auth.web.dto.LoginResponse
import com.aandiclub.auth.auth.web.dto.LoginUser
import com.aandiclub.auth.auth.web.v2.V2AuthController
import com.aandiclub.auth.common.error.v2.V2ErrorFactory
import com.aandiclub.auth.common.error.v2.V2ExceptionHandler
import com.aandiclub.auth.security.jwt.JwtProperties
import com.aandiclub.auth.security.service.JwtService
import com.aandiclub.auth.user.domain.UserRole
import io.kotest.core.spec.style.FunSpec
import io.mockk.every
import io.mockk.mockk
import org.springframework.http.MediaType
import org.springframework.test.web.reactive.server.WebTestClient
import reactor.core.publisher.Mono
import java.util.UUID

class V2AuthControllerTest : FunSpec({
	val authService = mockk<AuthService>()
	val jwtService = mockk<JwtService>()
	val jwtProperties = JwtProperties(
		issuer = "issuer",
		audience = "audience",
		secret = "secret",
		accessTokenExpSeconds = 3600,
		refreshTokenExpSeconds = 86400,
		clockSkewSeconds = 30,
	)
	val errorFactory = V2ErrorFactory()
	val webTestClient = WebTestClient.bindToController(V2AuthController(authService, jwtService, jwtProperties))
		.controllerAdvice(V2ExceptionHandler(errorFactory))
		.build()

	test("POST /v2/auth/login returns v2 envelope and sets cookie for web") {
		val userId = UUID.randomUUID()
		every { authService.login(any()) } returns Mono.just(
			LoginResponse(
				accessToken = "access",
				refreshToken = "refresh",
				expiresIn = 3600,
				tokenType = "Bearer",
				forcePasswordChange = false,
				user = LoginUser(userId, "user_01", UserRole.USER, "#NO001"),
			),
		)

		webTestClient.post()
			.uri("/v2/auth/login")
			.header("deviceOS", "WEB")
			.contentType(MediaType.APPLICATION_JSON)
			.bodyValue("""{"username":"user_01","password":"password"}""")
			.exchange()
			.expectStatus().isOk
			.expectCookie().valueEquals("refresh_token", "refresh")
			.expectBody()
			.jsonPath("$.success").isEqualTo(true)
			.jsonPath("$.data.accessToken").isEqualTo("access")
			.jsonPath("$.data.refreshToken").isEqualTo(null)
			.jsonPath("$.data.user.username").isEqualTo("user_01")
	}

	test("POST /v2/auth/login returns v2 envelope and token in body for non-web") {
		val userId = UUID.randomUUID()
		every { authService.login(any()) } returns Mono.just(
			LoginResponse(
				accessToken = "access",
				refreshToken = "refresh",
				expiresIn = 3600,
				tokenType = "Bearer",
				forcePasswordChange = false,
				user = LoginUser(userId, "user_01", UserRole.USER, "#NO001"),
			),
		)

		webTestClient.post()
			.uri("/v2/auth/login")
			.header("deviceOS", "ANDROID")
			.contentType(MediaType.APPLICATION_JSON)
			.bodyValue("""{"username":"user_01","password":"password"}""")
			.exchange()
			.expectStatus().isOk
			.expectCookie().doesNotExist("refresh_token")
			.expectBody()
			.jsonPath("$.success").isEqualTo(true)
			.jsonPath("$.data.accessToken").isEqualTo("access")
			.jsonPath("$.data.refreshToken").isEqualTo("refresh")
	}
})
