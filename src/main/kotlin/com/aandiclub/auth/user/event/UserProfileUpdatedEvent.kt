package com.aandiclub.auth.user.event

data class UserProfileUpdatedEvent(
	val eventId: String,
	val type: String,
	val occurredAt: String,
	val userId: String,
	val username: String? = null,
	val role: String? = null,
	val userTrack: String? = null,
	val cohort: Int? = null,
	val cohortOrder: Int? = null,
	val publicCode: String? = null,
	val nickname: String?,
	val profileImageUrl: String?,
	val version: Long,
)
