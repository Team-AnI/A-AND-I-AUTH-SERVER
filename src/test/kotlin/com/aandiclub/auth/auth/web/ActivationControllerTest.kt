package com.aandiclub.auth.auth.web

import com.aandiclub.auth.auth.service.AuthService
import com.aandiclub.auth.auth.web.dto.ActivateResponse
import com.aandiclub.auth.common.error.GlobalExceptionHandler
import com.aandiclub.auth.common.error.v2.V2ErrorFactory
import io.kotest.core.spec.style.FunSpec
import io.mockk.every
import io.mockk.mockk
import org.springframework.http.MediaType
import org.springframework.test.web.reactive.server.WebTestClient
import reactor.core.publisher.Mono

class ActivationControllerTest : FunSpec({
	val authService = mockk<AuthService>()
	val webTestClient = WebTestClient.bindToController(ActivationController(authService))
		.controllerAdvice(GlobalExceptionHandler(V2ErrorFactory()))
		.build()

	test("POST /activate returns success") {
		every { authService.activate(any()) } returns Mono.just(ActivateResponse(success = true))

		webTestClient.post()
			.uri("/activate")
			.contentType(MediaType.APPLICATION_JSON)
			.bodyValue("""{"token":"invite-token","password":"new-password-123"}""")
			.exchange()
			.expectStatus().isOk
			.expectBody()
				.jsonPath("$.success").isEqualTo(true)
				.jsonPath("$.data.success").isEqualTo(true)
	}

	test("POST /activate rejects invalid username format") {
		webTestClient.post()
			.uri("/activate")
			.contentType(MediaType.APPLICATION_JSON)
			.bodyValue("""{"token":"invite-token","password":"new-password-123","username":"Invalid Name"}""")
			.exchange()
			.expectStatus().isBadRequest
			.expectBody()
			.jsonPath("$.success").isEqualTo(false)
			.jsonPath("$.error.code").isEqualTo("INVALID_REQUEST")
			.jsonPath("$.error.message").isEqualTo("올바르지 않은 아이디 형식입니다. 영대소문자숫자만 사용가능합니다.")
	}

	test("POST /activate accepts uppercase username input") {
		every { authService.activate(any()) } returns Mono.just(ActivateResponse(success = true))

		webTestClient.post()
			.uri("/activate")
			.contentType(MediaType.APPLICATION_JSON)
			.bodyValue("""{"token":"invite-token","password":"new-password-123","username":"Member_09"}""")
			.exchange()
			.expectStatus().isOk
			.expectBody()
			.jsonPath("$.success").isEqualTo(true)
			.jsonPath("$.data.success").isEqualTo(true)
	}
})
