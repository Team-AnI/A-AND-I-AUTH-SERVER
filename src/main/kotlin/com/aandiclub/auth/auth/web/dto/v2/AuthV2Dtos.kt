package com.aandiclub.auth.auth.web.dto.v2

import com.aandiclub.auth.user.domain.UserRole
import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.Pattern
import jakarta.validation.constraints.Size
import java.util.UUID

data class V2LoginRequest(
	@field:NotBlank(message = "username is required")
	val username: String,
	@field:NotBlank(message = "password is required")
	val password: String,
)

data class V2RefreshRequest(
	val refreshToken: String? = null,
)

data class V2LogoutRequest(
	val refreshToken: String? = null,
)

data class V2ActivateRequest(
	@field:NotBlank(message = "token is required")
	val token: String,
	@field:NotBlank(message = "password is required")
	@field:Size(min = 12, max = 128, message = "password length must be between 12 and 128")
	val password: String,
	@field:Size(min = 3, max = 64, message = "username length must be between 3 and 64")
	@field:Pattern(
		regexp = "^[A-Za-z0-9_]+$",
		message = "올바르지 않은 아이디 형식입니다. 영대소문자숫자만 사용가능합니다.",
	)
	val username: String? = null,
)

data class V2LoginResponse(
	val accessToken: String,
	val refreshToken: String?,
	val expiresIn: Long,
	val tokenType: String,
	val forcePasswordChange: Boolean,
	val user: V2LoginUser,
)

data class V2LoginUser(
	val id: UUID,
	val username: String,
	val role: UserRole,
	val publicCode: String,
)

data class V2RefreshResponse(
	val accessToken: String,
	val expiresIn: Long,
)

data class V2LogoutResponse(
	val loggedOut: Boolean,
)

data class V2ActivateResponse(
	val activated: Boolean,
)
