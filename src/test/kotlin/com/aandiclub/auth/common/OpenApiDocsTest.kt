package com.aandiclub.auth.common

import io.kotest.core.extensions.Extension
import io.kotest.core.spec.style.StringSpec
import io.kotest.extensions.spring.SpringExtension
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.context.ApplicationContext
import org.springframework.test.web.reactive.server.WebTestClient

@SpringBootTest
class OpenApiDocsTest : StringSpec() {

	@Autowired
	private lateinit var applicationContext: ApplicationContext

	override fun extensions(): List<Extension> = listOf(SpringExtension)

	init {
		"GET /v3/api-docs should be publicly accessible" {
			webClient().get()
				.uri("/v3/api-docs")
				.exchange()
				.expectStatus().isOk
				.expectBody()
				.jsonPath("$.openapi").exists()
				.jsonPath("$.paths['/v1/me'].post.requestBody.content['multipart/form-data']").exists()
		}

		"GET /v3/api-docs/v1 should expose only v1-compatible paths" {
			webClient().get()
				.uri("/v3/api-docs/v1")
				.exchange()
				.expectStatus().isOk
				.expectBody()
				.jsonPath("$.info.version").isEqualTo("v1")
				.jsonPath("$.paths['/v1/me']").exists()
				.jsonPath("$.paths['/v2/me']").doesNotExist()
				.jsonPath("$.components.securitySchemes.bearerAuth.scheme").isEqualTo("bearer")
		}

		"GET /v3/api-docs/v2 should expose only v2 paths and v2 auth scheme" {
			webClient().get()
				.uri("/v3/api-docs/v2")
				.exchange()
				.expectStatus().isOk
				.expectBody()
				.jsonPath("$.info.version").isEqualTo("v2")
				.jsonPath("$.paths['/v2/me']").exists()
				.jsonPath("$.paths['/v1/me']").doesNotExist()
				.jsonPath("$.components.securitySchemes.authenticateHeader.name").isEqualTo("Authenticate")
				.jsonPath("$.paths['/v2/me'].get.security[0].authenticateHeader").isArray()
	}

		"GET /swagger-ui.html should be publicly accessible" {
			webClient().get()
				.uri("/swagger-ui.html")
				.exchange()
				.expectStatus().is3xxRedirection
		}
	}

	private fun webClient(): WebTestClient = WebTestClient.bindToApplicationContext(applicationContext).build()
}
