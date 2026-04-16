package com.aandiclub.auth

import io.kotest.core.extensions.Extension
import io.kotest.core.spec.style.StringSpec
import io.kotest.extensions.spring.SpringExtension
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.context.ApplicationContext
import org.springframework.test.web.reactive.server.WebTestClient

@SpringBootTest
class AuthApplicationTests : StringSpec() {

	@Autowired
	private lateinit var applicationContext: ApplicationContext

	override fun extensions(): List<Extension> = listOf(SpringExtension)

	init {
		"GET /api/ping returns standardized success response" {
			val webTestClient = WebTestClient.bindToApplicationContext(applicationContext).build()
			webTestClient.get()
				.uri("/api/ping")
				.exchange()
				.expectStatus().isOk
				.expectBody()
				.jsonPath("$.success").isEqualTo(true)
				.jsonPath("$.data.message").isEqualTo("pong")
				.jsonPath("$.error").doesNotExist()
		}

		"GET /api/ping/error returns standardized error response" {
			val webTestClient = WebTestClient.bindToApplicationContext(applicationContext).build()
			webTestClient.get()
				.uri("/api/ping/error")
				.exchange()
				.expectStatus().isBadRequest
				.expectBody()
				.jsonPath("$.success").isEqualTo(false)
				.jsonPath("$.error.code").isEqualTo("INVALID_REQUEST")
				.jsonPath("$.error.message").isEqualTo("강제 검증 오류입니다.")
		}
	}
}
