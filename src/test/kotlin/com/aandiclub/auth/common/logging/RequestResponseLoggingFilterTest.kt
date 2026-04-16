package com.aandiclub.auth.common.logging

import ch.qos.logback.classic.Level
import ch.qos.logback.classic.Logger
import ch.qos.logback.classic.spi.ILoggingEvent
import ch.qos.logback.core.read.ListAppender
import com.aandiclub.auth.common.api.v2.V2ApiResponse
import com.aandiclub.auth.common.error.AppException
import com.aandiclub.auth.common.error.ErrorCode
import com.aandiclub.auth.common.error.v2.V2ErrorFactory
import com.aandiclub.auth.common.error.GlobalExceptionHandler
import com.fasterxml.jackson.databind.ObjectMapper
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.shouldBe
import org.slf4j.LoggerFactory
import org.springframework.http.MediaType
import org.springframework.mock.env.MockEnvironment
import org.springframework.test.web.reactive.server.WebTestClient
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import reactor.core.publisher.Mono

class RequestResponseLoggingFilterTest : FunSpec({
	val objectMapper = ObjectMapper().findAndRegisterModules()
	val errorFactory = V2ErrorFactory()
	val environment = MockEnvironment()
		.withProperty("spring.application.name", "auth")
		.withProperty("spring.application.instance-id", "test-instance")
		.withProperty("app.env", "test")
		.withProperty("app.version", "1.2.3")
	val filter = RequestResponseLoggingFilter(objectMapper, ApiLogFactory(environment, errorFactory))
	val logger = LoggerFactory.getLogger(RequestResponseLoggingFilter.API_JSON_LOGGER_NAME) as Logger
	val appender = ListAppender<ILoggingEvent>().apply {
		start()
	}

	beforeSpec {
		logger.level = Level.INFO
		logger.addAppender(appender)
		logger.isAdditive = false
	}

	afterSpec {
		logger.detachAppender(appender)
	}

	beforeTest {
		appender.list.clear()
	}

	test("success responses are logged as structured API JSON with masking") {
		val spec: WebTestClient.ControllerSpec = WebTestClient.bindToController(TestLoggingController())
		val client = spec.webFilter<WebTestClient.ControllerSpec>(filter).build()

		client.post()
			.uri("/v2/auth/login/han?source=mobile")
			.contentType(MediaType.APPLICATION_JSON)
			.header("deviceOS", "IOS")
			.header("Authenticate", "Bearer real-token")
			.header("timestamp", "2026-04-15T12:00:00Z")
			.header("User-Agent", "Kotest")
			.header("appVersion", "2.0.0")
			.bodyValue(
				"""
				{
				  "loginId": "hanseul",
				  "password": "super-secret-password",
				  "accessToken": "request-token"
				}
				""".trimIndent(),
			)
			.exchange()
			.expectStatus().isOk

		val payload = objectMapper.readTree(appender.list.single().formattedMessage)
		appender.list.single().level.toString() shouldBe "INFO"
		payload["level"].asText() shouldBe "INFO"
		payload["logType"].asText() shouldBe "API"
		payload["message"].asText() shouldBe "HTTP request completed"
		payload["service"]["domainCode"].asInt() shouldBe 2
		payload["headers"]["Authenticate"].asText() shouldBe "Bearer ****"
		payload["request"]["body"]["password"].asText() shouldBe "****"
		payload["request"]["body"]["accessToken"].asText() shouldBe "****"
		payload["request"]["body"]["loginId"].asText() shouldBe "han******"
		payload["response"]["success"].asBoolean() shouldBe true
		payload["response"]["data"]["accessToken"].asText() shouldBe "****"
		payload["response"]["data"]["refreshToken"].asText() shouldBe "****"
		payload["http"]["route"].asText() shouldBe "/v2/auth/login/{loginId}"
		payload["request"]["pathVariables"]["loginId"].asText() shouldBe "han******"
		payload["tags"].map { it.asText() } shouldContain "success"
	}

	test("failure responses are logged as structured API_ERROR JSON with normalized code") {
		val spec: WebTestClient.ControllerSpec = WebTestClient.bindToController(TestLoggingController())
			.controllerAdvice(GlobalExceptionHandler(errorFactory))
		val client = spec.webFilter<WebTestClient.ControllerSpec>(filter).build()

		client.post()
			.uri("/v2/auth/login/fail")
			.contentType(MediaType.APPLICATION_JSON)
			.header("deviceOS", "IOS")
			.header("timestamp", "2026-04-15T12:00:00Z")
			.bodyValue(
				"""
				{
				  "loginId": "hanseul",
				  "password": "wrong-password"
				}
				""".trimIndent(),
			)
			.exchange()
			.expectStatus().isUnauthorized

		val payload = objectMapper.readTree(appender.list.single().formattedMessage)
		appender.list.single().level.toString() shouldBe "WARN"
		payload["level"].asText() shouldBe "WARN"
		payload["logType"].asText() shouldBe "API_ERROR"
		payload["message"].asText() shouldBe "로그인 실패: 아이디 또는 비밀번호가 올바르지 않습니다."
		payload["response"]["success"].asBoolean() shouldBe false
		payload["response"]["error"]["code"].asInt() shouldBe 21101
		payload["response"]["error"]["message"].asText() shouldBe "아이디 또는 비밀번호가 올바르지 않습니다."
		payload["request"]["body"]["password"].asText() shouldBe "****"
		payload["tags"].map { it.asText() } shouldContain "fail"
	}
}) {
	@RestController
	@RequestMapping("/v2/auth")
	class TestLoggingController {
		@PostMapping("/login/{loginId}")
		fun login(
			@PathVariable loginId: String,
			@RequestBody request: Map<String, Any?>,
		): Mono<V2ApiResponse<Map<String, Any?>>> {
			if (loginId == "fail") {
				return Mono.error(AppException(ErrorCode.UNAUTHORIZED, "Invalid username or password."))
			}
			return Mono.just(
				V2ApiResponse.success(
					mapOf(
						"loginId" to loginId,
						"accessToken" to "issued-access-token",
						"refreshToken" to "issued-refresh-token",
						"echo" to request,
					),
				),
			)
		}
	}
}
