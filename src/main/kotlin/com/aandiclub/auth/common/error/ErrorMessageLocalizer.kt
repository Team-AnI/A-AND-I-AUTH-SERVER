package com.aandiclub.auth.common.error

object ErrorMessageLocalizer {
	private val exactMessages = mapOf(
		"Invalid request." to "잘못된 요청입니다.",
		"Unauthorized." to "인증이 필요합니다.",
		"Forbidden." to "접근 권한이 없습니다.",
		"Resource not found." to "리소스를 찾을 수 없습니다.",
		"Internal server error." to "서버 내부 오류가 발생했습니다.",
		"Authentication is required." to "인증이 필요합니다.",
		"You do not have permission to access this resource." to "해당 리소스에 접근할 권한이 없습니다.",
		"deviceOS header is required." to "deviceOS 헤더는 필수입니다.",
		"timestamp header is required." to "timestamp 헤더는 필수입니다.",
		"timestamp header must be epoch milliseconds or ISO-8601." to "timestamp 헤더는 epoch milliseconds 또는 ISO-8601 형식이어야 합니다.",
		"Origin is not allowed." to "허용되지 않은 도메인입니다.",
		"Requested CORS method is not allowed." to "허용되지 않은 CORS 메서드입니다.",
		"Requested CORS headers are not allowed." to "허용되지 않은 CORS 헤더가 포함되어 있습니다.",
		"Forced validation error." to "강제 검증 오류입니다.",
		"Invalid username or password." to "아이디 또는 비밀번호가 올바르지 않습니다.",
		"Invalid or expired invite token." to "초대 토큰이 올바르지 않거나 만료되었습니다.",
		"Requested username is not available." to "요청한 아이디는 사용할 수 없습니다.",
		"Refresh token is logged out." to "로그아웃된 리프레시 토큰입니다.",
		"Invalid token format." to "토큰 형식이 올바르지 않습니다.",
		"Invalid token signature." to "토큰 서명이 올바르지 않습니다.",
		"Invalid token issuer." to "토큰 발급자가 올바르지 않습니다.",
		"Invalid token audience." to "토큰 대상이 올바르지 않습니다.",
		"Unexpected token type." to "예상하지 못한 토큰 유형입니다.",
		"Missing token expiration." to "토큰 만료 시간이 없습니다.",
		"Token is expired." to "토큰이 만료되었습니다.",
		"Missing token issue time." to "토큰 발급 시간이 없습니다.",
		"Token issue time is invalid." to "토큰 발급 시간이 올바르지 않습니다.",
		"Invalid token subject." to "토큰 subject가 올바르지 않습니다.",
		"Missing username claim." to "토큰에 username 클레임이 없습니다.",
		"Invalid role claim." to "토큰의 role 클레임이 올바르지 않습니다.",
		"Missing token jti." to "토큰에 jti 값이 없습니다.",
		"Invalid token type claim." to "토큰의 type 클레임이 올바르지 않습니다.",
		"Failed to sign token." to "토큰 서명에 실패했습니다.",
		"User not found." to "사용자를 찾을 수 없습니다.",
		"Admin cannot change own role." to "관리자는 자신의 역할을 변경할 수 없습니다.",
		"Admin cannot update own account via admin endpoint." to "관리자는 관리자 엔드포인트로 자신의 계정을 수정할 수 없습니다.",
		"Admin cannot delete own account." to "관리자는 자신의 계정을 삭제할 수 없습니다.",
		"At least one updatable field is required." to "수정할 필드를 하나 이상 입력해야 합니다.",
		"At least one email is required." to "이메일을 하나 이상 입력해야 합니다.",
		"Failed to issue invite link." to "초대 링크 생성에 실패했습니다.",
		"Failed to issue invite expiration." to "초대 만료 시간 생성에 실패했습니다.",
		"Failed to allocate a valid sequence." to "유효한 시퀀스 할당에 실패했습니다.",
		"Failed to allocate username sequence." to "아이디 시퀀스 할당에 실패했습니다.",
		"Failed to allocate user code sequence." to "사용자 코드 시퀀스 할당에 실패했습니다.",
		"Failed to allocate a unique public code." to "고유한 공개 코드를 생성하지 못했습니다.",
		"Mail sender is not configured." to "메일 발신자 설정이 없습니다.",
		"Mail from address is not configured." to "메일 발신 주소 설정이 없습니다.",
		"Failed to send invite email." to "초대 메일 발송에 실패했습니다.",
		"nickname must be a text form field." to "nickname은 텍스트 form field여야 합니다.",
		"nickname must not be blank." to "nickname 값은 비어 있을 수 없습니다.",
		"At least one profile field is required." to "프로필 필드를 하나 이상 입력해야 합니다.",
		"profileImage and profileImageUrl cannot be used together." to "profileImage와 profileImageUrl은 함께 사용할 수 없습니다.",
		"Profile image upload is disabled." to "프로필 이미지 업로드가 비활성화되어 있습니다.",
		"Profile image bucket is not configured." to "프로필 이미지 버킷 설정이 없습니다.",
		"Unsupported profile image content type." to "지원하지 않는 프로필 이미지 content type입니다.",
		"profileImage content type is required." to "profileImage content type은 필수입니다.",
		"profileImage must not be empty." to "profileImage는 비어 있을 수 없습니다.",
		"profileImageUrl must not be blank." to "profileImageUrl 값은 비어 있을 수 없습니다.",
		"profileImageUrl must be a valid https URL." to "profileImageUrl은 올바른 https URL이어야 합니다.",
		"profileImageUrl host is not allowed." to "허용되지 않은 profileImageUrl 호스트입니다.",
		"Invalid user code format." to "사용자 코드 형식이 올바르지 않습니다.",
		"cohort order is out of supported range." to "cohort order가 지원 범위를 벗어났습니다.",
		"Requested cohortOrder is already in use." to "요청한 cohortOrder는 이미 사용 중입니다.",
	)

	private val requiredPattern = Regex("^([A-Za-z][A-Za-z0-9]*) is required$")
	private val blankPattern = Regex("^([A-Za-z][A-Za-z0-9]*) must not be blank\\.$")
	private val maxLengthPattern = Regex("^([A-Za-z][A-Za-z0-9]*) length must be less than or equal to (\\d+)$")
	private val betweenLengthPattern = Regex("^([A-Za-z][A-Za-z0-9]*) length must be between (\\d+) and (\\d+)$")
	private val minPattern = Regex("^([A-Za-z][A-Za-z0-9]*) must be greater than or equal to (\\d+)\\.?$")
	private val betweenPattern = Regex("^([A-Za-z][A-Za-z0-9]*) must be between (\\d+) and ([A-Za-z0-9_$]+)\\.?$")

	fun localize(message: String?): String {
		if (message.isNullOrBlank()) {
			return "오류가 발생했습니다."
		}

		exactMessages[message]?.let { return it }

		requiredPattern.matchEntire(message)?.let { match ->
			return "${match.groupValues[1]}는 필수입니다."
		}
		blankPattern.matchEntire(message)?.let { match ->
			return "${match.groupValues[1]} 값은 비어 있을 수 없습니다."
		}
		maxLengthPattern.matchEntire(message)?.let { match ->
			return "${match.groupValues[1]} 길이는 ${match.groupValues[2]} 이하여야 합니다."
		}
		betweenLengthPattern.matchEntire(message)?.let { match ->
			return "${match.groupValues[1]} 길이는 ${match.groupValues[2]} 이상 ${match.groupValues[3]} 이하여야 합니다."
		}
		minPattern.matchEntire(message)?.let { match ->
			return "${match.groupValues[1]}는 ${match.groupValues[2]} 이상이어야 합니다."
		}
		betweenPattern.matchEntire(message)?.let { match ->
			return "${match.groupValues[1]}는 ${match.groupValues[2]} 이상 ${match.groupValues[3]} 이하여야 합니다."
		}

		return message
	}
}
