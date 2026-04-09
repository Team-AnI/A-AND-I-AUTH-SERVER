package com.aandiclub.auth.user.web.v2

import com.aandiclub.auth.common.api.v2.V2ApiResponse
import com.aandiclub.auth.common.error.AppException
import com.aandiclub.auth.common.error.ErrorCode
import com.aandiclub.auth.security.auth.AuthenticatedUser
import com.aandiclub.auth.user.service.UserService
import com.aandiclub.auth.user.web.dto.ChangePasswordRequest
import com.aandiclub.auth.user.web.dto.CreateProfileImageUploadUrlRequest
import com.aandiclub.auth.user.web.dto.MeResponse
import com.aandiclub.auth.user.web.dto.UpdateProfileRequest
import com.aandiclub.auth.user.web.dto.UserLookupResponse
import com.aandiclub.auth.user.web.dto.v2.V2ChangePasswordRequest
import com.aandiclub.auth.user.web.dto.v2.V2ChangePasswordResponse
import com.aandiclub.auth.user.web.dto.v2.V2CreateProfileImageUploadUrlRequest
import com.aandiclub.auth.user.web.dto.v2.V2CreateProfileImageUploadUrlResponse
import com.aandiclub.auth.user.web.dto.v2.V2MeResponse
import com.aandiclub.auth.user.web.dto.v2.V2UpdateProfileRequest
import com.aandiclub.auth.user.web.dto.v2.V2UserLookupResponse
import jakarta.validation.Valid
import jakarta.validation.constraints.NotBlank
import org.springframework.http.MediaType
import org.springframework.http.codec.multipart.FilePart
import org.springframework.http.codec.multipart.FormFieldPart
import org.springframework.http.codec.multipart.Part
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.validation.annotation.Validated
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PatchMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RequestPart
import org.springframework.web.bind.annotation.RestController
import reactor.core.publisher.Mono

@RestController
@RequestMapping("/v2/me")
@Validated
class V2UserController(
	private val userService: UserService,
) {
	@GetMapping
	fun me(@AuthenticationPrincipal user: AuthenticatedUser): Mono<V2ApiResponse<V2MeResponse>> =
		userService.getMe(user).map { V2ApiResponse.success(it.toV2()) }

	@PatchMapping(consumes = [MediaType.MULTIPART_FORM_DATA_VALUE])
	fun updateProfile(
		@AuthenticationPrincipal user: AuthenticatedUser,
		@RequestPart("nickname", required = false) nickname: Part?,
		@RequestPart("profileImage", required = false) profileImage: FilePart?,
	): Mono<V2ApiResponse<V2MeResponse>> {
		val nicknameValue = when (nickname) {
			null -> null
			is FormFieldPart -> nickname.value()
			else -> return Mono.error(AppException(ErrorCode.INVALID_REQUEST, "nickname must be a text form field."))
		}
		return userService.updateProfile(user, nicknameValue, profileImage, null)
			.map { V2ApiResponse.success(it.toV2()) }
	}

	@PatchMapping(consumes = [MediaType.APPLICATION_JSON_VALUE])
	fun updateProfileAsJson(
		@AuthenticationPrincipal user: AuthenticatedUser,
		@Valid @RequestBody request: V2UpdateProfileRequest,
	): Mono<V2ApiResponse<V2MeResponse>> =
		userService.updateProfile(
			user = user,
			nickname = request.nickname,
			profileImage = null,
			profileImageUrl = request.profileImageUrl,
		).map { V2ApiResponse.success(it.toV2()) }

	@PostMapping("/profile-image/upload-url")
	fun createProfileImageUploadUrl(
		@AuthenticationPrincipal user: AuthenticatedUser,
		@Valid @RequestBody request: V2CreateProfileImageUploadUrlRequest,
	): Mono<V2ApiResponse<V2CreateProfileImageUploadUrlResponse>> =
		userService.createProfileImageUploadUrl(
			user,
			CreateProfileImageUploadUrlRequest(contentType = request.contentType, fileName = request.fileName),
		).map {
			V2ApiResponse.success(
				V2CreateProfileImageUploadUrlResponse(
					uploadUrl = it.uploadUrl,
					profileImageUrl = it.profileImageUrl,
					objectKey = it.objectKey,
					expiresInSeconds = it.expiresInSeconds,
				),
			)
		}

	@PatchMapping("/password")
	fun changePassword(
		@AuthenticationPrincipal user: AuthenticatedUser,
		@Valid @RequestBody request: V2ChangePasswordRequest,
	): Mono<V2ApiResponse<V2ChangePasswordResponse>> =
		userService.changePassword(
			user,
			ChangePasswordRequest(currentPassword = request.currentPassword, newPassword = request.newPassword),
		).map { V2ApiResponse.success(V2ChangePasswordResponse(changed = it.success)) }

	private fun MeResponse.toV2(): V2MeResponse =
		V2MeResponse(
			id = id,
			username = username,
			role = role,
			userTrack = userTrack,
			publicCode = publicCode,
			nickname = nickname,
			profileImageUrl = profileImageUrl,
		)
}

@RestController
@RequestMapping("/v2/users")
@Validated
class V2UserLookupController(
	private val userService: UserService,
) {
	@GetMapping("/lookup")
	fun lookupByPublicCode(
		@RequestParam("code")
		@NotBlank(message = "code is required")
		code: String,
	): Mono<V2ApiResponse<V2UserLookupResponse>> =
		userService.lookupByPublicCode(code).map { V2ApiResponse.success(it.toV2()) }

	private fun UserLookupResponse.toV2(): V2UserLookupResponse =
		V2UserLookupResponse(
			id = id,
			username = username,
			role = role,
			publicCode = publicCode,
			nickname = nickname,
			profileImageUrl = profileImageUrl,
		)
}
