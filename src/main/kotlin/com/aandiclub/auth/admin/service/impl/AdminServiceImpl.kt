package com.aandiclub.auth.admin.service.impl

import com.aandiclub.auth.admin.config.InviteProperties
import com.aandiclub.auth.admin.domain.UserInviteEntity
import com.aandiclub.auth.admin.invite.InviteTokenCacheService
import com.aandiclub.auth.admin.password.CredentialGenerator
import com.aandiclub.auth.admin.repository.UserInviteRepository
import com.aandiclub.auth.admin.service.AdminService
import com.aandiclub.auth.admin.service.InviteMailService
import com.aandiclub.auth.admin.sequence.UsernameSequenceService
import com.aandiclub.auth.admin.web.dto.AdminUserSummary
import com.aandiclub.auth.admin.web.dto.CreateAdminUserRequest
import com.aandiclub.auth.admin.web.dto.CreateAdminUserResponse
import com.aandiclub.auth.admin.web.dto.InviteMailRequest
import com.aandiclub.auth.admin.web.dto.InviteMailResponse
import com.aandiclub.auth.admin.web.dto.InviteMailTarget
import com.aandiclub.auth.admin.web.dto.ProvisionType
import com.aandiclub.auth.admin.web.dto.ResetPasswordResponse
import com.aandiclub.auth.admin.web.dto.UpdateUserRequest
import com.aandiclub.auth.admin.web.dto.UpdateUserResponse
import com.aandiclub.auth.admin.web.dto.UpdateUserRoleResponse
import com.aandiclub.auth.common.error.AppException
import com.aandiclub.auth.common.error.ErrorCode
import com.aandiclub.auth.security.service.PasswordService
import com.aandiclub.auth.security.token.TokenHashService
import com.aandiclub.auth.user.domain.UserEntity
import com.aandiclub.auth.user.domain.UserRole
import com.aandiclub.auth.user.domain.UserTrack
import com.aandiclub.auth.user.event.UserProfileEventPublisher
import com.aandiclub.auth.user.event.UserProfileUpdatedEvent
import com.aandiclub.auth.user.repository.UserRepository
import com.aandiclub.auth.user.service.UserPublicCodeService
import org.slf4j.LoggerFactory
import org.springframework.dao.DataIntegrityViolationException
import org.springframework.stereotype.Service
import reactor.core.publisher.Flux
import reactor.core.publisher.Mono
import java.time.Clock
import java.time.Duration
import java.util.Locale
import java.util.UUID

@Service
class AdminServiceImpl(
	private val userRepository: UserRepository,
	private val userInviteRepository: UserInviteRepository,
	private val inviteTokenCacheService: InviteTokenCacheService,
	private val usernameSequenceService: UsernameSequenceService,
	private val credentialGenerator: CredentialGenerator,
	private val passwordService: PasswordService,
	private val tokenHashService: TokenHashService,
	private val userPublicCodeService: UserPublicCodeService,
	private val userProfileEventPublisher: UserProfileEventPublisher,
	private val inviteProperties: InviteProperties,
	private val inviteMailService: InviteMailService,
	private val clock: Clock = Clock.systemUTC(),
) : AdminService {
	override fun getUsers(): Mono<List<AdminUserSummary>> =
		userRepository.findAll()
			.flatMap { toAdminUserSummary(it, clock.instant()) }
			.collectList()

	override fun createUser(request: CreateAdminUserRequest): Mono<CreateAdminUserResponse> =
		createUserWithUniquePublicCode(request)

	override fun resetPassword(userId: UUID): Mono<ResetPasswordResponse> =
		userRepository.findById(userId)
			.switchIfEmpty(Mono.error(AppException(ErrorCode.NOT_FOUND, "User not found.")))
			.flatMap { user ->
				val temporaryPassword = credentialGenerator.randomPassword(32)
				val hashedPassword = passwordService.hash(temporaryPassword)
				userRepository.save(
					user.copy(
						passwordHash = hashedPassword,
						forcePasswordChange = true,
					),
				).map {
					logger.warn("security_audit event=admin_password_reset user_id={} username={}", it.id, it.username)
					ResetPasswordResponse(temporaryPassword = temporaryPassword)
				}
			}

	override fun updateUserRole(
		targetUserId: UUID,
		role: UserRole,
		actorUserId: UUID,
	): Mono<UpdateUserRoleResponse> {
		if (targetUserId == actorUserId) {
			return Mono.error(AppException(ErrorCode.FORBIDDEN, "Admin cannot change own role."))
		}

		return userRepository.findById(targetUserId)
			.switchIfEmpty(Mono.error(AppException(ErrorCode.NOT_FOUND, "User not found.")))
			.flatMap { user ->
				resolveCohortOrderForUpdate(
					originalCohort = user.cohort,
					originalCohortOrder = user.cohortOrder,
					resolvedCohort = user.cohort,
				).flatMap { resolvedCohortOrder ->
					val resolvedTrack = userPublicCodeService.resolveTrack(
						role = role,
						requestedTrack = if (role == UserRole.USER) user.userTrack else null,
					)
					saveUpdatedUserRoleWithUniquePublicCode(
						user = user,
						role = role,
						resolvedTrack = resolvedTrack,
						cohortOrder = resolvedCohortOrder,
					).map { saved ->
						logger.warn(
							"security_audit event=admin_user_role_changed user_id={} username={} old_role={} new_role={} public_code={}",
							saved.id,
							saved.username,
							user.role,
							saved.role,
							saved.publicCode,
						)
						UpdateUserRoleResponse(
							id = requireNotNull(saved.id),
							username = saved.username,
							role = saved.role,
							userTrack = saved.userTrack,
							cohort = saved.cohort,
							cohortOrder = saved.cohortOrder,
							publicCode = saved.publicCode,
						)
					}
				}
			}
	}

	override fun updateUser(request: UpdateUserRequest, actorUserId: UUID): Mono<UpdateUserResponse> {
		if (request.userId == actorUserId) {
			return Mono.error(AppException(ErrorCode.FORBIDDEN, "Admin cannot update own account via admin endpoint."))
		}
		if (request.role == null && request.userTrack == null && request.cohort == null && request.nickname == null) {
			return Mono.error(AppException(ErrorCode.INVALID_REQUEST, "At least one updatable field is required."))
		}

		val normalizedNickname = request.nickname?.trim()?.let { nickname ->
			if (nickname.isEmpty()) {
				return Mono.error(AppException(ErrorCode.INVALID_REQUEST, "nickname must not be blank."))
			}
			if (!NICKNAME_PATTERN.matches(nickname)) {
				return Mono.error(
					AppException(
						ErrorCode.INVALID_REQUEST,
						"nickname allows only letters, numbers, spaces, underscores, hyphens, and dots.",
					),
				)
			}
			nickname
		}

		return userRepository.findById(request.userId)
			.switchIfEmpty(Mono.error(AppException(ErrorCode.NOT_FOUND, "User not found.")))
			.flatMap { user ->
				val resolvedRole = request.role ?: user.role
				val resolvedCohort = request.cohort ?: user.cohort
				val cohortOrderMono = resolveCohortOrderForUpdate(
					originalCohort = user.cohort,
					originalCohortOrder = user.cohortOrder,
					resolvedCohort = resolvedCohort,
				)

				cohortOrderMono.flatMap { resolvedCohortOrder ->
					val resolvedTrack = userPublicCodeService.resolveTrack(
						role = resolvedRole,
						requestedTrack = if (resolvedRole == UserRole.USER) request.userTrack ?: user.userTrack else null,
					)
					saveUpdatedUserWithUniquePublicCode(
						user = user,
						resolvedRole = resolvedRole,
						resolvedTrack = resolvedTrack,
						resolvedCohort = resolvedCohort,
						cohortOrder = resolvedCohortOrder,
						resolvedNickname = normalizedNickname ?: user.nickname,
					).map { saved ->
					logger.warn(
						"security_audit event=admin_user_updated user_id={} username={} old_role={} new_role={} old_track={} new_track={} old_cohort={} new_cohort={} old_cohort_order={} new_cohort_order={} public_code={}",
						saved.id,
						saved.username,
						user.role,
						saved.role,
						user.userTrack,
						saved.userTrack,
						user.cohort,
						saved.cohort,
						user.cohortOrder,
						saved.cohortOrder,
						saved.publicCode,
					)
					UpdateUserResponse(
						id = requireNotNull(saved.id),
						username = saved.username,
						role = saved.role,
						userTrack = saved.userTrack,
						cohort = saved.cohort,
						cohortOrder = saved.cohortOrder,
						publicCode = saved.publicCode,
						nickname = saved.nickname,
					)
				}
				}
			}
	}

	override fun deleteUser(targetUserId: UUID, actorUserId: UUID): Mono<Void> {
		if (targetUserId == actorUserId) {
			return Mono.error(AppException(ErrorCode.FORBIDDEN, "Admin cannot delete own account."))
		}

		return userRepository.findById(targetUserId)
			.switchIfEmpty(Mono.error(AppException(ErrorCode.NOT_FOUND, "User not found.")))
			.flatMap { user ->
				userInviteRepository.findByUserIdOrderByCreatedAtDesc(requireNotNull(user.id))
					.concatMap { inviteTokenCacheService.deleteToken(it.tokenHash) }
					.then(userRepository.deleteById(requireNotNull(user.id)))
					.then(
						Mono.fromRunnable {
							logger.warn("security_audit event=admin_user_deleted user_id={} username={}", user.id, user.username)
						},
					)
					.then()
				}
	}

	override fun sendInviteMail(request: InviteMailRequest): Mono<InviteMailResponse> =
		Mono.defer {
			val recipientEmails = request.recipientEmails()
			if (recipientEmails.isEmpty()) {
				return@defer Mono.error(AppException(ErrorCode.INVALID_REQUEST, "At least one email is required."))
			}
			val provisioningProfile = resolveInviteProvisioningProfile(
				rawUserTrack = request.userTrack,
				rawCohort = request.cohort,
				rawCohortOrder = request.cohortOrder,
			)

			Flux.fromIterable(recipientEmails)
				.concatMap { recipientEmail -> createInviteMailTarget(recipientEmail, request.role, provisioningProfile) }
				.collectList()
				.map { invites ->
					val singleInvite = invites.singleOrNull()
					InviteMailResponse(
						sentCount = invites.size,
						invites = invites,
						username = singleInvite?.username,
						role = singleInvite?.role,
						inviteExpiresAt = singleInvite?.inviteExpiresAt,
						cohort = singleInvite?.cohort,
						cohortOrder = singleInvite?.cohortOrder,
						userTrack = singleInvite?.userTrack,
						publicCode = singleInvite?.publicCode,
					)
				}
		}

	private fun createUserWithUniquePublicCode(
		request: CreateAdminUserRequest,
		attempt: Int = 0,
	): Mono<CreateAdminUserResponse> =
		nextValidUserSequence().flatMap { sequence ->
			val username = "user_${sequence.toString().padStart(2, '0')}"
			allocateCohortOrder(request.cohort).flatMap { cohortOrder ->
				val userTrack = userPublicCodeService.resolveTrack(request.role, null)
				val publicCode = userPublicCodeService.generate(
					role = request.role,
					userTrack = userTrack,
					cohort = request.cohort,
					cohortOrder = cohortOrder,
				)
				ensurePublicCodeAvailable(publicCode = publicCode)
					.flatMap { available ->
						if (!available) {
							retryCreateUserForPublicCodeConflict(request, attempt)
						} else {
							when (request.provisionType) {
								ProvisionType.PASSWORD -> createPasswordProvisionedUser(
									username = username,
									role = request.role,
									userTrack = userTrack,
									cohort = request.cohort,
									cohortOrder = cohortOrder,
									publicCode = publicCode,
								)
								ProvisionType.INVITE -> createInviteProvisionedUser(
									username = username,
									role = request.role,
									userTrack = userTrack,
									cohort = request.cohort,
									cohortOrder = cohortOrder,
									publicCode = publicCode,
								)
							}
						}
					}
			}
		}.onErrorResume(DataIntegrityViolationException::class.java) { ex ->
			handleCreatePublicCodeConflict(ex, attempt) { createUserWithUniquePublicCode(request, attempt + 1) }
		}

	private fun createInviteMailTarget(
		recipientEmail: String,
		role: UserRole,
		provisioningProfile: InviteProvisioningProfile,
		attempt: Int = 0,
	): Mono<InviteMailTarget> =
		nextValidUserSequence().flatMap { sequence ->
			val username = "user_${sequence.toString().padStart(2, '0')}"
			resolveInviteCohortOrder(
				cohort = provisioningProfile.cohort,
				requestedCohortOrder = provisioningProfile.cohortOrder,
			).flatMap { cohortOrder ->
				val publicCode = userPublicCodeService.generate(
					role = role,
					userTrack = provisioningProfile.userTrack,
					cohort = provisioningProfile.cohort,
					cohortOrder = cohortOrder,
				)
				ensurePublicCodeAvailable(publicCode = publicCode)
					.flatMap { available ->
						if (!available) {
							handleInvitePublicCodeConflict(provisioningProfile, attempt)
								.flatMap { createInviteMailTarget(recipientEmail, role, provisioningProfile, attempt + 1) }
						} else {
							createInviteProvisionedUser(
								username = username,
								role = role,
								userTrack = provisioningProfile.userTrack,
								cohort = provisioningProfile.cohort,
								cohortOrder = cohortOrder,
								publicCode = publicCode,
							).flatMap { created ->
								val inviteLink = created.inviteLink
									?: return@flatMap Mono.error(
										AppException(ErrorCode.INTERNAL_SERVER_ERROR, "Failed to issue invite link."),
									)
								val expiresAt = created.expiresAt
									?: return@flatMap Mono.error(
										AppException(ErrorCode.INTERNAL_SERVER_ERROR, "Failed to issue invite expiration."),
									)
								inviteMailService
									.sendInviteMail(
										toEmail = recipientEmail,
										username = created.username,
										role = created.role,
										inviteUrl = inviteLink,
										expiresAt = expiresAt,
										userTrack = created.userTrack.name,
										cohort = created.cohort,
										cohortOrder = created.cohortOrder,
										publicCode = created.publicCode,
									)
									.thenReturn(
										InviteMailTarget(
											email = recipientEmail,
											username = created.username,
											role = created.role,
											inviteExpiresAt = expiresAt,
											userTrack = created.userTrack.name,
											cohort = created.cohort,
											cohortOrder = created.cohortOrder,
											publicCode = created.publicCode,
										),
									)
							}
						}
					}
			}
		}.onErrorResume(DataIntegrityViolationException::class.java) { ex ->
			if (!isPublicCodeUniqueViolation(ex)) {
				Mono.error(ex)
			} else {
				handleInvitePublicCodeConflict(provisioningProfile, attempt)
					.flatMap { createInviteMailTarget(recipientEmail, role, provisioningProfile, attempt + 1) }
			}
		}

	private fun createPasswordProvisionedUser(
		username: String,
		role: UserRole,
		userTrack: UserTrack,
		cohort: Int,
		cohortOrder: Int,
		publicCode: String,
	): Mono<CreateAdminUserResponse> {
		val temporaryPassword = credentialGenerator.randomPassword(32)
		val hashedPassword = passwordService.hash(temporaryPassword)
		return userRepository.save(
			UserEntity(
				username = username,
				passwordHash = hashedPassword,
				role = role,
				userTrack = userTrack,
				cohort = cohort,
				cohortOrder = cohortOrder,
				publicCode = publicCode,
				forcePasswordChange = true,
				isActive = true,
			),
		).flatMap { saved ->
			userProfileEventPublisher.publishUserProfileUpdated(toUserProfileUpdatedEvent(saved))
				.thenReturn(saved)
		}.map { saved ->
			logger.warn(
				"security_audit event=admin_user_created type=password user_id={} username={} role={} track={} cohort={} cohort_order={} public_code={}",
				saved.id,
				saved.username,
				saved.role,
				saved.userTrack,
				saved.cohort,
				saved.cohortOrder,
				saved.publicCode,
			)
			CreateAdminUserResponse(
				id = requireNotNull(saved.id),
				username = saved.username,
				role = saved.role,
				userTrack = saved.userTrack,
				cohort = saved.cohort,
				cohortOrder = saved.cohortOrder,
				publicCode = saved.publicCode,
				provisionType = ProvisionType.PASSWORD,
				temporaryPassword = temporaryPassword,
			)
		}
	}

	private fun createInviteProvisionedUser(
		username: String,
		role: UserRole,
		userTrack: UserTrack,
		cohort: Int,
		cohortOrder: Int,
		publicCode: String,
	): Mono<CreateAdminUserResponse> {
		val rawInviteToken = credentialGenerator.randomToken()
		val hashedInviteToken = tokenHashService.sha256Hex(rawInviteToken)
		val placeholderPasswordHash = passwordService.hash(credentialGenerator.randomPassword(32))
		val now = clock.instant()
		val expiresAt = now.plus(Duration.ofHours(inviteProperties.expirationHours))
		return userRepository.save(
			UserEntity(
				username = username,
				passwordHash = placeholderPasswordHash,
				role = role,
				userTrack = userTrack,
				cohort = cohort,
				cohortOrder = cohortOrder,
				publicCode = publicCode,
				forcePasswordChange = true,
				isActive = false,
			),
		).flatMap { savedUser ->
			userInviteRepository.save(
				UserInviteEntity(
					userId = requireNotNull(savedUser.id),
					tokenHash = hashedInviteToken,
					expiresAt = expiresAt,
					createdAt = now,
				),
			).flatMap { savedInvite ->
				inviteTokenCacheService.cacheToken(savedInvite.tokenHash, rawInviteToken, expiresAt)
					.thenReturn(savedInvite)
			}.then(
				userProfileEventPublisher.publishUserProfileUpdated(toUserProfileUpdatedEvent(savedUser))
					.thenReturn(savedUser),
			).map { publishedUser ->
				logger.warn(
					"security_audit event=admin_user_created type=invite user_id={} username={} role={} track={} cohort={} cohort_order={} public_code={} expires_at={}",
					publishedUser.id,
					publishedUser.username,
					publishedUser.role,
					publishedUser.userTrack,
					publishedUser.cohort,
					publishedUser.cohortOrder,
					publishedUser.publicCode,
					expiresAt,
				)
				CreateAdminUserResponse(
					id = requireNotNull(publishedUser.id),
					username = publishedUser.username,
					role = publishedUser.role,
					userTrack = publishedUser.userTrack,
					cohort = publishedUser.cohort,
					cohortOrder = publishedUser.cohortOrder,
					publicCode = publishedUser.publicCode,
					provisionType = ProvisionType.INVITE,
					inviteLink = "${inviteProperties.activationBaseUrl}?token=$rawInviteToken",
					expiresAt = expiresAt,
				)
			}
		}
	}

	private fun saveUpdatedUserRoleWithUniquePublicCode(
		user: UserEntity,
		role: UserRole,
		resolvedTrack: UserTrack,
		cohortOrder: Int,
		attempt: Int = 0,
	): Mono<UserEntity> {
		val recalculatedPublicCode = userPublicCodeService.generate(
			role = role,
			userTrack = resolvedTrack,
			cohort = user.cohort,
			cohortOrder = cohortOrder,
		)
		return ensurePublicCodeAvailable(
			publicCode = recalculatedPublicCode,
			excludedUserId = requireNotNull(user.id),
		).flatMap { available ->
			if (!available) {
				retryUpdatedUserForPublicCodeConflict(user.cohort, attempt) { nextCohortOrder ->
					saveUpdatedUserRoleWithUniquePublicCode(
						user = user,
						role = role,
						resolvedTrack = resolvedTrack,
						cohortOrder = nextCohortOrder,
						attempt = attempt + 1,
					)
				}
			} else {
				userRepository.save(
					user.copy(
						role = role,
						userTrack = resolvedTrack,
						cohortOrder = cohortOrder,
						publicCode = recalculatedPublicCode,
					),
				).flatMap { saved ->
					userProfileEventPublisher.publishUserProfileUpdated(toUserProfileUpdatedEvent(saved))
						.thenReturn(saved)
				}
			}
		}.onErrorResume(DataIntegrityViolationException::class.java) { ex ->
			handleUpdatePublicCodeConflict(ex, user.cohort, attempt) { nextCohortOrder ->
				saveUpdatedUserRoleWithUniquePublicCode(
					user = user,
					role = role,
					resolvedTrack = resolvedTrack,
					cohortOrder = nextCohortOrder,
					attempt = attempt + 1,
				)
			}
		}
	}

	private fun saveUpdatedUserWithUniquePublicCode(
		user: UserEntity,
		resolvedRole: UserRole,
		resolvedTrack: UserTrack,
		resolvedCohort: Int,
		cohortOrder: Int,
		resolvedNickname: String?,
		attempt: Int = 0,
	): Mono<UserEntity> {
		val recalculatedPublicCode = userPublicCodeService.generate(
			role = resolvedRole,
			userTrack = resolvedTrack,
			cohort = resolvedCohort,
			cohortOrder = cohortOrder,
		)
		return ensurePublicCodeAvailable(
			publicCode = recalculatedPublicCode,
			excludedUserId = requireNotNull(user.id),
		).flatMap { available ->
			if (!available) {
				retryUpdatedUserForPublicCodeConflict(resolvedCohort, attempt) { nextCohortOrder ->
					saveUpdatedUserWithUniquePublicCode(
						user = user,
						resolvedRole = resolvedRole,
						resolvedTrack = resolvedTrack,
						resolvedCohort = resolvedCohort,
						cohortOrder = nextCohortOrder,
						resolvedNickname = resolvedNickname,
						attempt = attempt + 1,
					)
				}
			} else {
				userRepository.save(
					user.copy(
						role = resolvedRole,
						userTrack = resolvedTrack,
						cohort = resolvedCohort,
						cohortOrder = cohortOrder,
						publicCode = recalculatedPublicCode,
						nickname = resolvedNickname,
					),
				).flatMap { saved ->
					userProfileEventPublisher.publishUserProfileUpdated(toUserProfileUpdatedEvent(saved))
						.thenReturn(saved)
				}
			}
		}.onErrorResume(DataIntegrityViolationException::class.java) { ex ->
			handleUpdatePublicCodeConflict(ex, resolvedCohort, attempt) { nextCohortOrder ->
				saveUpdatedUserWithUniquePublicCode(
					user = user,
					resolvedRole = resolvedRole,
					resolvedTrack = resolvedTrack,
					resolvedCohort = resolvedCohort,
					cohortOrder = nextCohortOrder,
					resolvedNickname = resolvedNickname,
					attempt = attempt + 1,
				)
			}
		}
	}

	private fun resolveInviteProvisioningProfile(
		rawUserTrack: String?,
		rawCohort: Int?,
		rawCohortOrder: Int?,
	): InviteProvisioningProfile {
		val normalizedTrack = rawUserTrack?.trim()?.uppercase()
			?.takeIf { it.isNotEmpty() }
			?: DEFAULT_USER_TRACK
		if (normalizedTrack !in ALLOWED_USER_TRACKS) {
			throw AppException(
				ErrorCode.INVALID_REQUEST,
				"userTrack must be one of ${ALLOWED_USER_TRACKS.joinToString(", ")}.",
			)
		}
		val userTrack = UserTrack.valueOf(normalizedTrack)

			val cohort = rawCohort ?: 0
			if (cohort < 0) {
				throw AppException(ErrorCode.INVALID_REQUEST, "cohort must be greater than or equal to 0.")
			}
			if (cohort > MAX_COHORT) {
				throw AppException(ErrorCode.INVALID_REQUEST, "cohort must be between 0 and $MAX_COHORT.")
			}

		if (rawCohortOrder != null && rawCohortOrder < 0) {
			throw AppException(ErrorCode.INVALID_REQUEST, "cohortOrder must be greater than or equal to 0.")
		}
		if (rawCohortOrder != null && rawCohortOrder > MAX_COHORT_ORDER) {
			throw AppException(
				ErrorCode.INVALID_REQUEST,
				"cohortOrder must be less than or equal to $MAX_COHORT_ORDER.",
			)
		}
		// 0 (or null) is treated as "auto-allocate next cohort order".
		val cohortOrder = rawCohortOrder?.takeIf { it >= MIN_COHORT_ORDER }

		return InviteProvisioningProfile(
			userTrack = userTrack,
			cohort = cohort,
			cohortOrder = cohortOrder,
		)
	}

	private data class InviteProvisioningProfile(
		val userTrack: UserTrack,
		val cohort: Int,
		val cohortOrder: Int?,
	)

	private fun resolveInviteCohortOrder(cohort: Int, requestedCohortOrder: Int?): Mono<Int> =
		requestedCohortOrder?.let { Mono.just(it) } ?: allocateCohortOrder(cohort)

	private fun resolveCohortOrderForUpdate(
		originalCohort: Int,
		originalCohortOrder: Int,
		resolvedCohort: Int,
	): Mono<Int> =
		if (resolvedCohort != originalCohort || originalCohortOrder !in MIN_COHORT_ORDER..MAX_COHORT_ORDER) {
			allocateCohortOrder(resolvedCohort)
		} else {
			Mono.just(originalCohortOrder)
		}

	private fun allocateCohortOrder(cohort: Int): Mono<Int> =
		nextPositiveSequence(fetch = { usernameSequenceService.nextCohortOrderSequence(cohort) })
			.flatMap { sequence ->
				if (sequence > MAX_COHORT_ORDER.toLong()) {
					Mono.error(
						AppException(
							ErrorCode.INTERNAL_SERVER_ERROR,
							"Cohort order capacity exceeded for cohort $cohort.",
						),
					)
				} else {
					Mono.just(sequence.toInt())
				}
			}

	private fun nextValidUserSequence(): Mono<Long> =
		nextPositiveSequence(fetch = { usernameSequenceService.nextSequence() })

	private fun nextPositiveSequence(fetch: () -> Mono<Long>, attempt: Int = 0): Mono<Long> =
		fetch().flatMap { sequence ->
			if (sequence >= MIN_SEQUENCE_VALUE) {
				Mono.just(sequence)
			} else if (attempt + 1 >= SEQUENCE_RETRY_LIMIT) {
				Mono.error(AppException(ErrorCode.INTERNAL_SERVER_ERROR, "Failed to allocate a valid sequence."))
			} else {
				nextPositiveSequence(fetch, attempt + 1)
			}
		}

	private fun ensurePublicCodeAvailable(publicCode: String, excludedUserId: UUID? = null): Mono<Boolean> =
		userRepository.findByPublicCode(publicCode)
			.map { existing -> excludedUserId != null && existing.id == excludedUserId }
			.defaultIfEmpty(true)

	private fun retryCreateUserForPublicCodeConflict(
		request: CreateAdminUserRequest,
		attempt: Int,
	): Mono<CreateAdminUserResponse> =
		if (attempt + 1 >= PUBLIC_CODE_RETRY_LIMIT) {
			Mono.error(exhaustedUniquePublicCodeError())
		} else {
			createUserWithUniquePublicCode(request, attempt + 1)
		}

	private fun handleInvitePublicCodeConflict(
		provisioningProfile: InviteProvisioningProfile,
		attempt: Int,
	): Mono<Unit> =
		if (provisioningProfile.cohortOrder != null) {
			Mono.error(AppException(ErrorCode.INVALID_REQUEST, "Requested cohortOrder is already in use."))
		} else if (attempt + 1 >= PUBLIC_CODE_RETRY_LIMIT) {
			Mono.error(exhaustedUniquePublicCodeError())
		} else {
			Mono.just(Unit)
		}

	private fun retryUpdatedUserForPublicCodeConflict(
		cohort: Int,
		attempt: Int,
		retry: (Int) -> Mono<UserEntity>,
	): Mono<UserEntity> =
		if (attempt + 1 >= PUBLIC_CODE_RETRY_LIMIT) {
			Mono.error(exhaustedUniquePublicCodeError())
		} else {
			allocateCohortOrder(cohort).flatMap(retry)
		}

	private fun handleCreatePublicCodeConflict(
		ex: DataIntegrityViolationException,
		attempt: Int,
		retry: () -> Mono<CreateAdminUserResponse>,
	): Mono<CreateAdminUserResponse> =
		if (!isPublicCodeUniqueViolation(ex)) {
			Mono.error(ex)
		} else if (attempt + 1 >= PUBLIC_CODE_RETRY_LIMIT) {
			Mono.error(exhaustedUniquePublicCodeError())
		} else {
			retry()
		}

	private fun handleUpdatePublicCodeConflict(
		ex: DataIntegrityViolationException,
		cohort: Int,
		attempt: Int,
		retry: (Int) -> Mono<UserEntity>,
	): Mono<UserEntity> =
		if (!isPublicCodeUniqueViolation(ex)) {
			Mono.error(ex)
		} else {
			retryUpdatedUserForPublicCodeConflict(cohort, attempt, retry)
		}

	private fun exhaustedUniquePublicCodeError(): AppException =
		AppException(ErrorCode.INTERNAL_SERVER_ERROR, "Failed to allocate a unique public code.")

	private fun isPublicCodeUniqueViolation(ex: DataIntegrityViolationException): Boolean {
		val message = (ex.mostSpecificCause?.message ?: ex.message).orEmpty().lowercase(Locale.ROOT)
		return message.contains("ux_users_public_code") || message.contains("public_code")
	}

	private fun toAdminUserSummary(user: UserEntity, now: java.time.Instant): Mono<AdminUserSummary> {
		val baseSummary = AdminUserSummary(
			id = requireNotNull(user.id),
			username = user.username,
			role = user.role,
			userTrack = user.userTrack,
			cohort = user.cohort,
			cohortOrder = user.cohortOrder,
			publicCode = user.publicCode,
			isActive = user.isActive,
			forcePasswordChange = user.forcePasswordChange,
			nickname = user.nickname,
		)
		if (user.isActive) {
			return Mono.just(baseSummary)
		}

		return userInviteRepository
			.findByUserIdOrderByCreatedAtDesc(requireNotNull(user.id))
			.filter { it.usedAt == null && it.expiresAt.isAfter(now) }
			.next()
			.flatMap { invite ->
				inviteTokenCacheService.findToken(invite.tokenHash)
					.map { token ->
						baseSummary.copy(
							inviteLink = "${inviteProperties.activationBaseUrl}?token=$token",
							inviteExpiresAt = invite.expiresAt,
						)
					}
					.defaultIfEmpty(baseSummary.copy(inviteExpiresAt = invite.expiresAt))
			}
			.switchIfEmpty(Mono.just(baseSummary))
	}

	private fun toUserProfileUpdatedEvent(entity: UserEntity): UserProfileUpdatedEvent =
		UserProfileUpdatedEvent(
			eventId = UUID.randomUUID().toString(),
			type = USER_PROFILE_UPDATED_EVENT_TYPE,
			occurredAt = entity.updatedAt.toString(),
			userId = requireNotNull(entity.id).toString(),
			username = entity.username,
			role = entity.role.name,
			userTrack = entity.userTrack.name,
			cohort = entity.cohort,
			cohortOrder = entity.cohortOrder,
			publicCode = entity.publicCode,
			nickname = entity.nickname,
			profileImageUrl = entity.profileImageUrl,
			version = entity.profileVersion,
		)

	companion object {
		private val logger = LoggerFactory.getLogger(AdminServiceImpl::class.java)
		private const val DEFAULT_USER_TRACK = "NO"
			private val ALLOWED_USER_TRACKS = setOf("NO", "FL", "SP")
			private val NICKNAME_PATTERN = Regex("^[\\p{L}\\p{N} _.-]{1,40}$")
			private const val USER_PROFILE_UPDATED_EVENT_TYPE = "UserProfileUpdated"
			private const val MAX_COHORT = 9
			private const val MIN_COHORT_ORDER = 1
			private const val MAX_COHORT_ORDER = 99
			private const val PUBLIC_CODE_RETRY_LIMIT = 10
			private const val MIN_SEQUENCE_VALUE = 1L
			private const val SEQUENCE_RETRY_LIMIT = 10
		}
	}
