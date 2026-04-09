package com.aandiclub.auth.common.web.v2

object V2ApiPaths {
	private const val BASE_PATH = "/v2"

	fun isV2(path: String): Boolean = path == BASE_PATH || path.startsWith("$BASE_PATH/")
}
