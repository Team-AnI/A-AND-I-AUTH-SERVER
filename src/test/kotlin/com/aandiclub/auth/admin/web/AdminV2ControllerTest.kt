package com.aandiclub.auth.admin.web

import com.aandiclub.auth.admin.service.AdminService
import com.aandiclub.auth.admin.web.dto.InviteMailResponse
import com.aandiclub.auth.admin.web.dto.InviteMailTarget
import com.aandiclub.auth.common.error.GlobalExceptionHandler
import com.aandiclub.auth.user.domain.UserRole
import io.kotest.core.spec.style.FunSpec
import io.mockk.every
import io.mockk.mockk
import org.springframework.http.MediaType
import org.springframework.test.web.reactive.server.WebTestClient
import reactor.core.publisher.Mono
import java.time.Instant

/**
 * Admin V2 Controller Tests
 */
class AdminV2ControllerTest : FunSpec() {
	private val adminService = mockk<AdminService>(relaxed = true)
	private val webTestClient = WebTestClient.bindToController(AdminV2Controller(adminService))
		.controllerAdvice(GlobalExceptionHandler())
		.build()

	init {
		test("POST /v2/admin/invite-mail returns invite payload (Multiple)") {
			every { adminService.sendInviteMailV2(any()) } returns Mono.just(
				InviteMailResponse(
					sentCount = 1,
					invites = listOf(
						InviteMailTarget(
							email = "v2_member@aandi.club",
							username = "user_02",
							role = UserRole.USER,
							inviteExpiresAt = Instant.parse("2026-03-06T00:00:00Z"),
						),
					),
					username = "user_02",
					role = UserRole.USER,
					inviteExpiresAt = Instant.parse("2026-03-06T00:00:00Z"),
				),
			)

			webTestClient.post()
				.uri("/v2/admin/invite-mail")
				.contentType(MediaType.APPLICATION_JSON)
				.bodyValue("""{"emails":["v2_member@aandi.club"],"role":"USER"}""")
				.exchange()
				.expectStatus().isOk
				.expectBody()
				.jsonPath("$.success").isEqualTo(true)
				.jsonPath("$.data.sentCount").isEqualTo(1)
				.jsonPath("$.data.username").isEqualTo("user_02")
		}

		test("POST /v2/admin/invite-mail with empty emails returns bad request") {
			webTestClient.post()
				.uri("/v2/admin/invite-mail")
				.contentType(MediaType.APPLICATION_JSON)
				.bodyValue("""{"emails":[],"role":"USER"}""")
				.exchange()
				.expectStatus().isBadRequest
				.expectBody()
				.jsonPath("$.success").isEqualTo(false)
				.jsonPath("$.error.code").isEqualTo("INVALID_REQUEST")
		}
	}
}
