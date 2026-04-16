package com.aandiclub.auth.security.config

import org.springframework.boot.context.properties.ConfigurationProperties

@ConfigurationProperties(prefix = "app.cors")
data class AppCorsProperties(
	val allowedOrigins: String = "",
	val allowedMethods: String = "GET,POST,PUT,PATCH,DELETE,OPTIONS",
	val allowedHeaders: String = "Authorization,Authenticate,Content-Type,Accept,Origin,X-Requested-With,deviceOS,timestamp,salt,appVersion,App-Version,X-App-Version",
	val exposedHeaders: String = "",
	val allowCredentials: Boolean = true,
	val maxAgeSeconds: Long = 3600,
) {
	fun allowedOriginsList(): List<String> = csv(allowedOrigins)

	fun allowedMethodsList(): List<String> = csv(allowedMethods)

	fun allowedHeadersList(): List<String> = csv(allowedHeaders)

	fun exposedHeadersList(): List<String> = csv(exposedHeaders)

	private fun csv(raw: String): List<String> = raw
		.split(",")
		.map { it.trim() }
		.filter { it.isNotBlank() }
}
