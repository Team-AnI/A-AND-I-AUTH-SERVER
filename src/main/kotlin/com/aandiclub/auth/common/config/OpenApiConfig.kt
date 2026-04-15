package com.aandiclub.auth.common.config

import io.swagger.v3.oas.models.Components
import io.swagger.v3.oas.models.OpenAPI
import io.swagger.v3.oas.models.info.Info
import io.swagger.v3.oas.models.security.SecurityRequirement
import io.swagger.v3.oas.models.security.SecurityScheme
import io.swagger.v3.oas.models.parameters.Parameter
import io.swagger.v3.oas.models.servers.Server
import org.springdoc.core.customizers.OpenApiCustomizer
import org.springdoc.core.customizers.OperationCustomizer
import org.springdoc.core.models.GroupedOpenApi
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.core.annotation.AnnotatedElementUtils
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.web.bind.annotation.DeleteMapping
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PatchMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.PutMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.method.HandlerMethod

@Configuration
@EnableConfigurationProperties(OpenApiProperties::class)
class OpenApiConfig(
	private val openApiProperties: OpenApiProperties,
) {

	@Bean
	fun openApi(): OpenAPI {
		val openApi = OpenAPI()
			.info(
				Info()
					.title("AANDI Club Auth API")
					.description("Core authentication and authorization service APIs")
					.version("all"),
			)
			.components(baseComponents())

		if (openApiProperties.serverUrl.isNotBlank()) {
			openApi.addServersItem(Server().url(openApiProperties.serverUrl))
		}

		return openApi
	}

	@Bean
	fun v1GroupedOpenApi(): GroupedOpenApi =
		GroupedOpenApi.builder()
			.group("v1")
			.pathsToMatch("/v1/**", "/activate", "/api/ping/**")
			.addOpenApiCustomizer(versionInfoCustomizer(version = "v1"))
			.addOperationCustomizer(v1OperationCustomizer())
			.build()

	@Bean
	fun v2GroupedOpenApi(): GroupedOpenApi =
		GroupedOpenApi.builder()
			.group("v2")
			.pathsToMatch("/v2/**")
			.addOpenApiCustomizer(versionInfoCustomizer(version = "v2"))
			.addOperationCustomizer(v2OperationCustomizer())
			.build()

	private fun versionInfoCustomizer(version: String): OpenApiCustomizer =
		OpenApiCustomizer { openApi ->
			openApi.info = Info()
				.title("AANDI Club Auth API $version")
				.description(
					when (version) {
						"v2" -> "A&I v2 communication contract APIs"
						else -> "Legacy v1 APIs kept for backward compatibility"
					},
				)
				.version(version)

			if (openApiProperties.serverUrl.isNotBlank()) {
				openApi.servers = listOf(Server().url(openApiProperties.serverUrl))
			}
		}

	private fun v1OperationCustomizer(): OperationCustomizer =
		OperationCustomizer { operation, handlerMethod ->
			val path = resolvePath(handlerMethod)
			if (isProtectedV1Path(path)) {
				operation.addSecurityItem(SecurityRequirement().addList(BEARER_AUTH_SCHEME))
			}
			operation
		}

	private fun v2OperationCustomizer(): OperationCustomizer =
		OperationCustomizer { operation, handlerMethod ->
			val path = resolvePath(handlerMethod)
			addHeaderParameter(
				operation = operation,
				name = "deviceOS",
				required = true,
				description = "Client device OS identifier.",
			)
			addHeaderParameter(
				operation = operation,
				name = "timestamp",
				required = true,
				description = "Request timestamp. Server currently accepts ISO-8601 or epoch milliseconds.",
			)
			addHeaderParameter(
				operation = operation,
				name = "salt",
				required = false,
				description = "Optional request salt.",
			)
			if (isProtectedV2Path(path)) {
				operation.addSecurityItem(SecurityRequirement().addList(AUTHENTICATE_HEADER_SCHEME))
			}
			operation
		}

	private fun addHeaderParameter(
		operation: io.swagger.v3.oas.models.Operation,
		name: String,
		required: Boolean,
		description: String,
	) {
		val exists = operation.parameters?.any { it.`in` == "header" && it.name == name } == true
		if (exists) {
			return
		}
		operation.addParametersItem(
			Parameter()
				.`in`("header")
				.name(name)
				.required(required)
				.description(description),
		)
	}

	private fun baseComponents(): Components =
		Components()
			.addSecuritySchemes(
				BEARER_AUTH_SCHEME,
				SecurityScheme()
					.type(SecurityScheme.Type.HTTP)
					.scheme("bearer")
					.bearerFormat("JWT"),
			)
			.addSecuritySchemes(
				AUTHENTICATE_HEADER_SCHEME,
				SecurityScheme()
					.type(SecurityScheme.Type.APIKEY)
					.`in`(SecurityScheme.In.HEADER)
					.name("Authenticate")
					.description("A&I v2 auth header. Format: Bearer {accessToken}"),
			)

	private fun resolvePath(handlerMethod: HandlerMethod): String {
		val classPath = resolveClassPath(handlerMethod)
		val methodPath = resolveMethodPath(handlerMethod)
		return normalizePath("$classPath/$methodPath")
	}

	private fun resolveClassPath(handlerMethod: HandlerMethod): String =
		AnnotatedElementUtils.findMergedAnnotation(handlerMethod.beanType, RequestMapping::class.java)
			?.let { firstPath(it.path, it.value) }
			.orEmpty()

	private fun resolveMethodPath(handlerMethod: HandlerMethod): String =
		AnnotatedElementUtils.findMergedAnnotation(handlerMethod.method, RequestMapping::class.java)
			?.let { firstPath(it.path, it.value) }
			?: AnnotatedElementUtils.findMergedAnnotation(handlerMethod.method, GetMapping::class.java)
				?.let { firstPath(it.path, it.value) }
			?: AnnotatedElementUtils.findMergedAnnotation(handlerMethod.method, PostMapping::class.java)
				?.let { firstPath(it.path, it.value) }
			?: AnnotatedElementUtils.findMergedAnnotation(handlerMethod.method, PutMapping::class.java)
				?.let { firstPath(it.path, it.value) }
			?: AnnotatedElementUtils.findMergedAnnotation(handlerMethod.method, PatchMapping::class.java)
				?.let { firstPath(it.path, it.value) }
			?: AnnotatedElementUtils.findMergedAnnotation(handlerMethod.method, DeleteMapping::class.java)
				?.let { firstPath(it.path, it.value) }
			.orEmpty()

	private fun firstPath(path: Array<String>, value: Array<String>): String =
		(path.firstOrNull { it.isNotBlank() } ?: value.firstOrNull { it.isNotBlank() }).orEmpty()

	private fun normalizePath(path: String): String =
		path.replace(Regex("/+"), "/").removeSuffix("/").ifBlank { "/" }

	private fun isProtectedV1Path(path: String): Boolean =
		path.startsWith("/v1/me") || path == "/v1/users/lookup" || path.startsWith("/v1/admin")

	private fun isProtectedV2Path(path: String): Boolean =
		path.startsWith("/v2/me") || path == "/v2/users/lookup" || path.startsWith("/v2/admin")

	companion object {
		private const val BEARER_AUTH_SCHEME = "bearerAuth"
		private const val AUTHENTICATE_HEADER_SCHEME = "authenticateHeader"
	}
}
