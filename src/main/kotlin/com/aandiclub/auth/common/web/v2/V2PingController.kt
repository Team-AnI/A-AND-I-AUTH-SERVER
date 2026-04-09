package com.aandiclub.auth.common.web.v2

import com.aandiclub.auth.common.api.v2.V2ApiResponse
import com.aandiclub.auth.common.error.AppException
import com.aandiclub.auth.common.error.ErrorCode
import com.aandiclub.auth.common.service.PingService
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/v2/ping")
class V2PingController(
	private val pingService: PingService,
) {
	@GetMapping
	fun ping(): V2ApiResponse<Map<String, String>> =
		V2ApiResponse.success(mapOf("message" to pingService.ping()))

	@GetMapping("/error")
	fun error(): V2ApiResponse<Nothing> {
		throw AppException(ErrorCode.INVALID_REQUEST, "Forced validation error.")
	}
}
