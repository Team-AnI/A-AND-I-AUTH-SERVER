package com.aandiclub.auth.admin.web.v2

import com.aandiclub.auth.admin.service.AdminService
import com.aandiclub.auth.admin.web.dto.AdminUserSummary
import com.aandiclub.auth.admin.web.dto.CreateAdminUserRequest
import com.aandiclub.auth.admin.web.dto.CreateAdminUserResponse
import com.aandiclub.auth.admin.web.dto.InviteMailRequest
import com.aandiclub.auth.admin.web.dto.InviteMailResponse
import com.aandiclub.auth.admin.web.dto.InviteMailTarget
import com.aandiclub.auth.admin.web.dto.UpdateUserRequest
import com.aandiclub.auth.admin.web.dto.UpdateUserResponse
import com.aandiclub.auth.admin.web.dto.UpdateUserRoleResponse
import com.aandiclub.auth.admin.web.dto.v2.V2AdminPingResponse
import com.aandiclub.auth.admin.web.dto.v2.V2AdminUserSummary
import com.aandiclub.auth.admin.web.dto.v2.V2CreateAdminUserRequest
import com.aandiclub.auth.admin.web.dto.v2.V2CreateAdminUserResponse
import com.aandiclub.auth.admin.web.dto.v2.V2DeleteUserResponse
import com.aandiclub.auth.admin.web.dto.v2.V2InviteMailRequest
import com.aandiclub.auth.admin.web.dto.v2.V2InviteMailResponse
import com.aandiclub.auth.admin.web.dto.v2.V2InviteMailTarget
import com.aandiclub.auth.admin.web.dto.v2.V2ResetPasswordResponse
import com.aandiclub.auth.admin.web.dto.v2.V2UpdateUserRequest
import com.aandiclub.auth.admin.web.dto.v2.V2UpdateUserResponse
import com.aandiclub.auth.admin.web.dto.v2.V2UpdateUserRoleRequest
import com.aandiclub.auth.admin.web.dto.v2.V2UpdateUserRoleResponse
import com.aandiclub.auth.common.api.v2.V2ApiResponse
import com.aandiclub.auth.security.auth.AuthenticatedUser
import jakarta.validation.Valid
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.validation.annotation.Validated
import org.springframework.web.bind.annotation.DeleteMapping
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PatchMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import reactor.core.publisher.Mono
import java.util.UUID

@RestController
@RequestMapping("/v2/admin")
@Validated
class V2AdminController(
	private val adminService: AdminService,
) {
	@GetMapping("/ping")
	fun ping(): V2ApiResponse<V2AdminPingResponse> = V2ApiResponse.success(V2AdminPingResponse(ok = true))

	@GetMapping("/users")
	fun getUsers(): Mono<V2ApiResponse<List<V2AdminUserSummary>>> =
		adminService.getUsers().map { users -> V2ApiResponse.success(users.map { it.toV2() }) }

	@PostMapping("/users")
	fun createUser(@Valid @RequestBody request: V2CreateAdminUserRequest): Mono<V2ApiResponse<V2CreateAdminUserResponse>> =
		adminService.createUser(
			CreateAdminUserRequest(
				cohort = request.cohort,
				role = request.role,
				provisionType = request.provisionType,
			),
		).map { V2ApiResponse.success(it.toV2()) }

	@PostMapping("/invite-mail")
	fun sendInviteMail(@Valid @RequestBody request: V2InviteMailRequest): Mono<V2ApiResponse<V2InviteMailResponse>> =
		adminService.sendInviteMail(
			InviteMailRequest(
				emails = request.emails,
				role = request.role,
				cohort = request.cohort,
				cohortOrder = request.cohortOrder,
				userTrack = request.userTrack,
			),
		).map { V2ApiResponse.success(it.toV2()) }

	@PostMapping("/users/{id}/password/reset")
	fun resetPassword(@PathVariable id: UUID): Mono<V2ApiResponse<V2ResetPasswordResponse>> =
		adminService.resetPassword(id).map { V2ApiResponse.success(V2ResetPasswordResponse(temporaryPassword = it.temporaryPassword)) }

	@PatchMapping("/users/{id}/role")
	fun updateUserRole(
		@PathVariable id: UUID,
		@Valid @RequestBody request: V2UpdateUserRoleRequest,
		@AuthenticationPrincipal actor: AuthenticatedUser,
	): Mono<V2ApiResponse<V2UpdateUserRoleResponse>> =
		adminService.updateUserRole(
			targetUserId = id,
			role = request.role,
			actorUserId = actor.userId,
		).map { V2ApiResponse.success(it.toV2()) }

	@PatchMapping("/users/{id}")
	fun updateUser(
		@PathVariable id: UUID,
		@Valid @RequestBody request: V2UpdateUserRequest,
		@AuthenticationPrincipal actor: AuthenticatedUser,
	): Mono<V2ApiResponse<V2UpdateUserResponse>> =
		adminService.updateUser(
			request = UpdateUserRequest(
				userId = id,
				role = request.role,
				userTrack = request.userTrack,
				cohort = request.cohort,
				nickname = request.nickname,
			),
			actorUserId = actor.userId,
		).map { V2ApiResponse.success(it.toV2()) }

	@DeleteMapping("/users/{id}")
	fun deleteUser(
		@PathVariable id: UUID,
		@AuthenticationPrincipal actor: AuthenticatedUser,
	): Mono<V2ApiResponse<V2DeleteUserResponse>> =
		adminService.deleteUser(targetUserId = id, actorUserId = actor.userId)
			.thenReturn(V2ApiResponse.success(V2DeleteUserResponse(userId = id, deleted = true)))

	private fun AdminUserSummary.toV2(): V2AdminUserSummary =
		V2AdminUserSummary(
			id = id,
			username = username,
			role = role,
			userTrack = userTrack,
			cohort = cohort,
			cohortOrder = cohortOrder,
			publicCode = publicCode,
			isActive = isActive,
			forcePasswordChange = forcePasswordChange,
			nickname = nickname,
			inviteLink = inviteLink,
			inviteExpiresAt = inviteExpiresAt,
		)

	private fun CreateAdminUserResponse.toV2(): V2CreateAdminUserResponse =
		V2CreateAdminUserResponse(
			id = id,
			username = username,
			role = role,
			userTrack = userTrack,
			cohort = cohort,
			cohortOrder = cohortOrder,
			publicCode = publicCode,
			provisionType = provisionType,
			inviteLink = inviteLink,
			expiresAt = expiresAt,
			temporaryPassword = temporaryPassword,
		)

	private fun InviteMailResponse.toV2(): V2InviteMailResponse =
		V2InviteMailResponse(
			sentCount = sentCount,
			invites = invites.map { it.toV2() },
			username = username,
			role = role,
			inviteExpiresAt = inviteExpiresAt,
			cohort = cohort,
			cohortOrder = cohortOrder,
			userTrack = userTrack,
			publicCode = publicCode,
		)

	private fun InviteMailTarget.toV2(): V2InviteMailTarget =
		V2InviteMailTarget(
			email = email,
			username = username,
			role = role,
			inviteExpiresAt = inviteExpiresAt,
			cohort = cohort,
			cohortOrder = cohortOrder,
			userTrack = userTrack,
			publicCode = publicCode,
		)

	private fun UpdateUserRoleResponse.toV2(): V2UpdateUserRoleResponse =
		V2UpdateUserRoleResponse(
			id = id,
			username = username,
			role = role,
			userTrack = userTrack,
			cohort = cohort,
			cohortOrder = cohortOrder,
			publicCode = publicCode,
		)

	private fun UpdateUserResponse.toV2(): V2UpdateUserResponse =
		V2UpdateUserResponse(
			id = id,
			username = username,
			role = role,
			userTrack = userTrack,
			cohort = cohort,
			cohortOrder = cohortOrder,
			publicCode = publicCode,
			nickname = nickname,
		)
}
