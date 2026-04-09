package com.aandiclub.auth.auth.web

import com.aandiclub.auth.auth.service.AuthService
import com.aandiclub.auth.auth.web.dto.LoginResponse
import com.aandiclub.auth.auth.web.dto.LoginUser
import com.aandiclub.auth.auth.web.v2.V2AuthController
import com.aandiclub.auth.common.error.v2.V2ErrorFactory
import com.aandiclub.auth.common.error.v2.V2ExceptionHandler
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
	val errorFactory = V2ErrorFactory()
	val webTestClient = WebTestClient.bindToController(V2AuthController(authService))
		.controllerAdvice(V2ExceptionHandler(errorFactory))
		.build()

	test("POST /v2/auth/login returns v2 envelope") {
		every { authService.login(any()) } returns Mono.just(
			LoginResponse(
				accessToken = "access",
				refreshToken = "refresh",
				expiresIn = 3600,
				tokenType = "Bearer",
				forcePasswordChange = false,
				user = LoginUser(UUID.randomUUID(), "user_01", UserRole.USER, "#NO001"),
			),
		)

		webTestClient.post()
			.uri("/v2/auth/login")
			.contentType(MediaType.APPLICATION_JSON)
			.bodyValue("""{"username":"user_01","password":"password"}""")
			.exchange()
			.expectStatus().isOk
			.expectBody()
			.jsonPath("$.success").isEqualTo(true)
			.jsonPath("$.data.accessToken").isEqualTo("access")
			.jsonPath("$.data.user.username").isEqualTo("user_01")
			.jsonPath("$.error").doesNotExist()
	}
})
