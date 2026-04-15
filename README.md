# auth

`aandiclub.com` 핵심 인증 서비스입니다.

## Local Run (Docker Compose)
사전 준비:
```bash
cp .env.example .env
```

필수 확인(게이트웨이/인증 값 일치):
- `JWT_SECRET` == `AUTH_JWT_SECRET`
- `JWT_ISSUER` == `AUTH_ISSUER_URI`
- `JWT_AUDIENCE` == `AUTH_AUDIENCE`
- `DB_MIGRATION_ENABLED=true`
- `DB_JDBC_URL` 과 `DB_R2DBC_URL` 은 반드시 같은 DB를 가리켜야 함

```bash
docker compose up --build
```

기본 포트:
- Auth API: `http://localhost:8080`
- Swagger UI: `http://localhost:8080/swagger-ui.html`

## OpenAPI / Swagger
- Swagger UI: `/swagger-ui.html`
- 통합 문서: `/v3/api-docs`
- v1 문서: `/v3/api-docs/v1`
- v2 문서: `/v3/api-docs/v2`

게이트웨이 뒤에서 운영할 경우 아래 경로가 함께 라우팅되어야 Swagger UI에서 v1/v2 드롭다운이 정상 동작합니다.
- `/swagger-ui.html`
- `/swagger-ui/**`
- `/v3/api-docs/**`

## API Versioning
- 기존 v1 API는 유지합니다.
- 신규 A&I 규약 대응 API는 `/v2/**`로 제공합니다.
- 원칙:
  - v1 요청/응답 스펙은 변경하지 않음
  - v2는 Controller/DTO/응답 래퍼/예외 응답/헤더 처리 계층 중심으로 분리
  - Service/도메인/Repository 로직은 최대한 재사용

## A&I v2 Contract Summary

### Common Response Envelope
v2 응답은 아래 구조를 따릅니다.

```json
{
  "success": true,
  "data": {},
  "error": null,
  "timestamp": "2026-04-09T12:00:00Z"
}
```

실패 시:

```json
{
  "success": false,
  "data": null,
  "error": {
    "code": 23101,
    "message": "deviceOS header is required.",
    "value": "MISSING_DEVICE_OS_HEADER",
    "alert": "deviceOS header is required."
  },
  "timestamp": "2026-04-09T12:00:00Z"
}
```

### Common Headers
v2 API는 아래 헤더 체계를 사용합니다.
- `deviceOS`: 필수
- `timestamp`: 필수
- `Authenticate`: 보호된 API에서 필수, 형식 `Bearer {accessToken}`
- `salt`: 선택

현재 서버는 `timestamp`를 아래 둘 다 허용합니다.
- ISO-8601 문자열
- epoch milliseconds

### v2 Error Code Structure
에러 코드는 5자리 정수 구조를 따릅니다.

`[서비스 1자리][분류 1자리][상세 3자리]`

서비스 코드:
- `1`: Gateway
- `2`: Auth
- `3`: User
- `4`: Report
- `5`: Judge
- `6`: Blog
- `9`: Common

분류 코드:
- `0`: 일반
- `1`: 인증
- `2`: 인가
- `3`: 검증
- `4`: 비즈니스
- `5`: 리소스 없음
- `6`: 중복/충돌
- `7`: 외부 시스템
- `8`: 내부 오류

### v2 Error Table in This Server
현재 구현 기준으로 v2 오류 응답은 다음 원칙을 따릅니다.
- `error.message`: 개발자용 메시지
- `error.alert`: 유저용 메시지
- 현재 구현상 대부분 `alert == message` 입니다.
- 동일한 메시지라도 호출 경로에 따라 서비스 코드 prefix(`2xxxx`, `3xxxx`, `9xxxx`)가 달라질 수 있습니다.

#### 1) 공통 / 보안 / 헤더 오류

| 적용 경로 | 코드 | value | 개발자용 메시지 (`message`) | 유저용 메시지 (`alert`) |
|---|---:|---|---|---|
| `/v2/auth/**`, `/v2/activate`, `/v2/admin/invite-mail`, `/v2/admin/ping` | `23101` | `MISSING_DEVICE_OS_HEADER` | `deviceOS header is required.` | `deviceOS header is required.` |
| `/v2/me/**`, `/v2/users/**`, `/v2/admin/users/**` | `33101` | `MISSING_DEVICE_OS_HEADER` | `deviceOS header is required.` | `deviceOS header is required.` |
| `/v2/auth/**`, `/v2/activate`, `/v2/admin/invite-mail`, `/v2/admin/ping` | `23102` | `MISSING_TIMESTAMP_HEADER` | `timestamp header is required.` | `timestamp header is required.` |
| `/v2/me/**`, `/v2/users/**`, `/v2/admin/users/**` | `33102` | `MISSING_TIMESTAMP_HEADER` | `timestamp header is required.` | `timestamp header is required.` |
| `/v2/auth/**`, `/v2/activate`, `/v2/admin/invite-mail`, `/v2/admin/ping` | `23103` | `INVALID_TIMESTAMP_HEADER` | `timestamp header must be epoch milliseconds or ISO-8601.` | `timestamp header must be epoch milliseconds or ISO-8601.` |
| `/v2/me/**`, `/v2/users/**`, `/v2/admin/users/**` | `33103` | `INVALID_TIMESTAMP_HEADER` | `timestamp header must be epoch milliseconds or ISO-8601.` | `timestamp header must be epoch milliseconds or ISO-8601.` |
| 보호된 Auth 계열 v2 경로 | `21101` | `UNAUTHORIZED` | `Authentication is required.` | `Authentication is required.` |
| 보호된 User 계열 v2 경로 | `31101` | `UNAUTHORIZED` | `Authentication is required.` | `Authentication is required.` |
| Auth 계열 v2 경로 인가 실패 | `22101` | `FORBIDDEN` | `You do not have permission to access this resource.` | `You do not have permission to access this resource.` |
| User 계열 v2 경로 인가 실패 | `32101` | `FORBIDDEN` | `You do not have permission to access this resource.` | `You do not have permission to access this resource.` |

#### 2) Auth / Token / Activation 오류

| 적용 경로 | 코드 | value | 개발자용 메시지 (`message`) | 유저용 메시지 (`alert`) |
|---|---:|---|---|---|
| `/v2/auth/login`, `/v2/me/password` | `21101` / `31101` | `UNAUTHORIZED` | `Invalid username or password.` | `Invalid username or password.` |
| `/v2/auth/refresh` | `21101` | `UNAUTHORIZED` | `Refresh token is logged out.` | `Refresh token is logged out.` |
| `/v2/activate` | `21101` | `UNAUTHORIZED` | `Invalid or expired invite token.` | `Invalid or expired invite token.` |
| `/v2/activate` | `23101` | `INVALID_REQUEST` | `Requested username is not available.` | `Requested username is not available.` |
| `/v2/auth/refresh`, `/v2/me/**`, `/v2/admin/**` 보호 경로 | `21101` / `31101` | `UNAUTHORIZED` | `Invalid token format.` | `Invalid token format.` |
| `/v2/auth/refresh`, `/v2/me/**`, `/v2/admin/**` 보호 경로 | `21101` / `31101` | `UNAUTHORIZED` | `Invalid token signature.` | `Invalid token signature.` |
| `/v2/auth/refresh`, `/v2/me/**`, `/v2/admin/**` 보호 경로 | `21101` / `31101` | `UNAUTHORIZED` | `Invalid token issuer.` | `Invalid token issuer.` |
| `/v2/auth/refresh`, `/v2/me/**`, `/v2/admin/**` 보호 경로 | `21101` / `31101` | `UNAUTHORIZED` | `Invalid token audience.` | `Invalid token audience.` |
| `/v2/auth/refresh`, `/v2/me/**`, `/v2/admin/**` 보호 경로 | `21101` / `31101` | `UNAUTHORIZED` | `Unexpected token type.` | `Unexpected token type.` |
| `/v2/auth/refresh`, `/v2/me/**`, `/v2/admin/**` 보호 경로 | `21101` / `31101` | `UNAUTHORIZED` | `Missing token expiration.` | `Missing token expiration.` |
| `/v2/auth/refresh`, `/v2/me/**`, `/v2/admin/**` 보호 경로 | `21101` / `31101` | `UNAUTHORIZED` | `Token is expired.` | `Token is expired.` |
| `/v2/auth/refresh`, `/v2/me/**`, `/v2/admin/**` 보호 경로 | `21101` / `31101` | `UNAUTHORIZED` | `Missing token issue time.` | `Missing token issue time.` |
| `/v2/auth/refresh`, `/v2/me/**`, `/v2/admin/**` 보호 경로 | `21101` / `31101` | `UNAUTHORIZED` | `Token issue time is invalid.` | `Token issue time is invalid.` |
| `/v2/auth/refresh`, `/v2/me/**`, `/v2/admin/**` 보호 경로 | `21101` / `31101` | `UNAUTHORIZED` | `Invalid token subject.` | `Invalid token subject.` |
| `/v2/auth/refresh`, `/v2/me/**`, `/v2/admin/**` 보호 경로 | `21101` / `31101` | `UNAUTHORIZED` | `Missing username claim.` | `Missing username claim.` |
| `/v2/auth/refresh`, `/v2/me/**`, `/v2/admin/**` 보호 경로 | `21101` / `31101` | `UNAUTHORIZED` | `Invalid role claim.` | `Invalid role claim.` |
| `/v2/auth/refresh`, `/v2/me/**`, `/v2/admin/**` 보호 경로 | `21101` / `31101` | `UNAUTHORIZED` | `Missing token jti.` | `Missing token jti.` |
| `/v2/auth/refresh`, `/v2/me/**`, `/v2/admin/**` 보호 경로 | `21101` / `31101` | `UNAUTHORIZED` | `Invalid token type claim.` | `Invalid token type claim.` |
| `/v2/auth/**` | `28101` | `INTERNAL_SERVER_ERROR` | `Failed to sign token.` | `Failed to sign token.` |

#### 3) User / Profile 오류

| 적용 경로 | 코드 | value | 개발자용 메시지 (`message`) | 유저용 메시지 (`alert`) |
|---|---:|---|---|---|
| `/v2/me`, `/v2/me/profile-image/upload-url`, `/v2/users/lookup` | `35101` | `NOT_FOUND` | `User not found.` | `User not found.` |
| `/v2/me` | `33101` | `INVALID_REQUEST` | `At least one profile field is required.` | `At least one profile field is required.` |
| `/v2/me` | `33101` | `INVALID_REQUEST` | `profileImage and profileImageUrl cannot be used together.` | `profileImage and profileImageUrl cannot be used together.` |
| `/v2/me` | `33101` | `INVALID_REQUEST` | `nickname must not be blank.` | `nickname must not be blank.` |
| `/v2/me` | `33101` | `INVALID_REQUEST` | `nickname must be a text form field.` | `nickname must be a text form field.` |
| `/v2/me` | `33101` | `INVALID_REQUEST` | `profileImageUrl must not be blank.` | `profileImageUrl must not be blank.` |
| `/v2/me` | `33101` | `INVALID_REQUEST` | `profileImageUrl must be a valid https URL.` | `profileImageUrl must be a valid https URL.` |
| `/v2/me` | `33101` | `INVALID_REQUEST` | `profileImageUrl host is not allowed.` | `profileImageUrl host is not allowed.` |
| `/v2/me` | `33101` | `INVALID_REQUEST` | `profileImage content type is required.` | `profileImage content type is required.` |
| `/v2/me`, `/v2/me/profile-image/upload-url` | `33101` | `INVALID_REQUEST` | `Unsupported profile image content type.` | `Unsupported profile image content type.` |
| `/v2/me` | `33101` | `INVALID_REQUEST` | `profileImage must not be empty.` | `profileImage must not be empty.` |
| `/v2/me`, `/v2/me/profile-image/upload-url` | `32101` | `FORBIDDEN` | `Profile image upload is disabled.` | `Profile image upload is disabled.` |
| `/v2/me`, `/v2/me/profile-image/upload-url` | `38101` | `INTERNAL_SERVER_ERROR` | `Profile image bucket is not configured.` | `Profile image bucket is not configured.` |
| `/v2/users/lookup` | `33101` | `INVALID_REQUEST` | `Invalid user code format.` | `Invalid user code format.` |
| `/v2/users/lookup` | `33101` | `INVALID_REQUEST` | `cohort must be between 0 and 9.` | `cohort must be between 0 and 9.` |
| `/v2/users/lookup` | `38101` | `INTERNAL_SERVER_ERROR` | `cohort order is out of supported range.` | `cohort order is out of supported range.` |

#### 4) Admin 오류

| 적용 경로 | 코드 | value | 개발자용 메시지 (`message`) | 유저용 메시지 (`alert`) |
|---|---:|---|---|---|
| `/v2/admin/users/{id}/role` | `32101` | `FORBIDDEN` | `Admin cannot change own role.` | `Admin cannot change own role.` |
| `/v2/admin/users/{id}` | `32101` | `FORBIDDEN` | `Admin cannot update own account via admin endpoint.` | `Admin cannot update own account via admin endpoint.` |
| `/v2/admin/users/{id}` | `32101` | `FORBIDDEN` | `Admin cannot delete own account.` | `Admin cannot delete own account.` |
| `/v2/admin/users`, `/v2/admin/users/{id}`, `/v2/admin/users/{id}/role` | `35101` | `NOT_FOUND` | `User not found.` | `User not found.` |
| `/v2/admin/users`, `/v2/admin/invite-mail` | `33101` / `23101` | `INVALID_REQUEST` | `At least one email is required.` | `At least one email is required.` |
| `/v2/admin/users/{id}` | `33101` | `INVALID_REQUEST` | `At least one updatable field is required.` | `At least one updatable field is required.` |
| `/v2/admin/users/{id}` | `33101` | `INVALID_REQUEST` | `nickname must not be blank.` | `nickname must not be blank.` |
| `/v2/admin/invite-mail` | `23101` | `INVALID_REQUEST` | `Requested cohortOrder is already in use.` | `Requested cohortOrder is already in use.` |
| `/v2/admin/invite-mail` | `23101` | `INVALID_REQUEST` | `cohort must be greater than or equal to 0.` | `cohort must be greater than or equal to 0.` |
| `/v2/admin/invite-mail` | `23101` | `INVALID_REQUEST` | `cohort must be between 0 and 9.` | `cohort must be between 0 and 9.` |
| `/v2/admin/invite-mail` | `23101` | `INVALID_REQUEST` | `cohortOrder must be greater than or equal to 0.` | `cohortOrder must be greater than or equal to 0.` |
| `/v2/admin/users`, `/v2/admin/users/{id}`, `/v2/admin/users/{id}/role` | `38101` | `INTERNAL_SERVER_ERROR` | `Failed to allocate a unique public code.` | `Failed to allocate a unique public code.` |
| `/v2/admin/users`, `/v2/admin/invite-mail` | `28101` / `38101` | `INTERNAL_SERVER_ERROR` | `Failed to allocate a valid sequence.` | `Failed to allocate a valid sequence.` |
| `/v2/admin/invite-mail` | `28101` | `INTERNAL_SERVER_ERROR` | `Failed to issue invite link.` | `Failed to issue invite link.` |
| `/v2/admin/invite-mail` | `28101` | `INTERNAL_SERVER_ERROR` | `Failed to issue invite expiration.` | `Failed to issue invite expiration.` |
| `/v2/admin/invite-mail` | `28101` | `INTERNAL_SERVER_ERROR` | `Failed to send invite email.` | `Failed to send invite email.` |
| `/v2/admin/invite-mail` | `28101` | `INTERNAL_SERVER_ERROR` | `Mail sender is not configured.` | `Mail sender is not configured.` |
| `/v2/admin/invite-mail` | `28101` | `INTERNAL_SERVER_ERROR` | `Mail from address is not configured.` | `Mail from address is not configured.` |

#### 5) Bean Validation / 요청 파싱 오류

| 적용 경로 | 코드 | value | 개발자용 메시지 (`message`) | 유저용 메시지 (`alert`) |
|---|---:|---|---|---|
| Auth 계열 v2 경로 | `23101` | `INVALID_REQUEST` | 첫 번째 DTO validation 메시지 또는 `Invalid request.` | 동일 |
| User 계열 v2 경로 | `33101` | `INVALID_REQUEST` | 첫 번째 DTO validation 메시지 또는 `Invalid request.` | 동일 |
| Common 계열 v2 경로 | `93101` | `INVALID_REQUEST` | 첫 번째 DTO validation 메시지 또는 `Invalid request.` | 동일 |

예시 validation 메시지:
- `username is required`
- `password is required`
- `newPassword length must be between 12 and 128`
- `emails must not be empty`
- `올바르지 않은 아이디 형식입니다. 영대소문자숫자만 사용가능합니다.`

#### 6) 참고 사항
- `/v2/admin/users/**` 는 현재 구현에서 User 서비스 코드(`3xxxx`)로 매핑됩니다.
- `/v2/admin/invite-mail`, `/v2/admin/ping` 는 현재 구현에서 Auth 서비스 코드(`2xxxx`)로 매핑됩니다.
- Admin 전용 서비스 코드가 따로 있는 것은 아니며, 현재는 경로 기반 매핑 결과를 그대로 사용합니다.
- 향후 `value` 와 `alert` 를 세분화하려면 `AppException` 생성 시 개별 값을 명시하도록 확장하는 것이 좋습니다.

### Current v2 Auth Header Behavior
- 공개 API
  - `/v2/auth/**`
  - `/v2/activate`
  - `/v2/ping/**`
- 보호 API
  - `/v2/me/**`
  - `/v2/users/lookup`
  - `/v2/admin/**`

보호 API는 `Authenticate: Bearer {accessToken}` 헤더가 필요합니다.

## Profile Image Upload (S3 Presigned URL)
- `POST /v1/me`를 `multipart/form-data`로 호출해 `nickname` + `profileImage`를 한 번에 처리
  - 서버가 이미지를 S3에 업로드한 뒤 사용자 프로필을 갱신
- (옵션) `POST /v1/me/profile-image/upload-url` presigned 업로드 방식도 지원
  - presigned 업로드 후 `PATCH /v1/me`에 `profileImageUrl`을 보내 사용자 프로필에 반영

필수 환경 변수:
- `APP_PROFILE_ALLOWED_IMAGE_HOSTS`: 저장 허용할 이미지 호스트(콤마 구분)
- `APP_PROFILE_IMAGE_ENABLED`: `true`로 설정 시 S3 업로드 URL 발급 활성화
- `APP_PROFILE_IMAGE_BUCKET`, `APP_PROFILE_IMAGE_REGION`
- `APP_PROFILE_IMAGE_KEY_PREFIX`(기본 `profiles`)
- `APP_PROFILE_IMAGE_PUBLIC_BASE_URL`(선택, CloudFront 사용 시)

## User CRUD Event
현재 구현은 유저 변경 이벤트를 `UserCreated` / `UserUpdated` / `UserDeleted`로 분리하지 않고, 변경 후 최신 사용자 스냅샷을 담는 `UserProfileUpdated` 이벤트 하나로 발행합니다.

CRUD별 발행 여부:
- Create: 발행됨 (`AdminServiceImpl.createUser`, 비밀번호 생성/초대 생성 모두 포함)
- Read: 발행되지 않음
- Update: 발행됨 (`UserServiceImpl.updateProfile`, `AdminServiceImpl.updateUser`, `AdminServiceImpl.updateUserRole`)
- Delete: 발행되지 않음 (`AdminServiceImpl.deleteUser`는 삭제 감사 로그만 남김)

SNS 발행 형식:
- Message body: 아래 JSON
- Message attribute: `eventType=UserProfileUpdated`
- FIFO Topic 사용 시:
  - `MessageGroupId=${APP_USER_PROFILE_EVENT_FIFO_MESSAGE_GROUP_ID:user-profile-updated}`
  - `MessageDeduplicationId=eventId`

메시지 바디 스키마:
```json
{
  "eventId": "uuid",
  "type": "UserProfileUpdated",
  "occurredAt": "2026-03-21T10:15:30Z",
  "userId": "uuid",
  "username": "user_01",
  "role": "USER",
  "userTrack": "NO",
  "cohort": 4,
  "cohortOrder": 1,
  "publicCode": "#NO401",
  "nickname": "andi",
  "profileImageUrl": "https://images.aandiclub.com/profiles/user_01.png",
  "version": 1
}
```

필드 설명:
- `eventId`: 이벤트 고유 ID (`UUID`)
- `type`: 현재 항상 `UserProfileUpdated`
- `occurredAt`: 사용자 레코드의 `updatedAt`
- `userId`: 사용자 ID
- `username`: 내부 username
- `role`: `ADMIN`, `ORGANIZER`, `USER`
- `userTrack`: `NO`, `FL`, `SP`
- `cohort`, `cohortOrder`, `publicCode`: 사용자 공개 식별 정보 계산에 사용되는 값
- `nickname`, `profileImageUrl`: 최신 프로필 값
- `version`: `users.profile_version`

CRUD 예시:

Create 시 예시:
```json
{
  "eventId": "9f4d1b9c-5dd4-4d05-93e4-53dc6740d9a3",
  "type": "UserProfileUpdated",
  "occurredAt": "2026-03-21T10:15:30Z",
  "userId": "a6d3eb0d-5174-4aa9-8f87-e1f91228a9c8",
  "username": "user_01",
  "role": "USER",
  "userTrack": "NO",
  "cohort": 4,
  "cohortOrder": 1,
  "publicCode": "#NO401",
  "nickname": null,
  "profileImageUrl": null,
  "version": 0
}
```

Update 시 예시:
```json
{
  "eventId": "3a3c6f82-4ec4-4f91-a57f-2b4d745c4b31",
  "type": "UserProfileUpdated",
  "occurredAt": "2026-03-21T10:18:44Z",
  "userId": "a6d3eb0d-5174-4aa9-8f87-e1f91228a9c8",
  "username": "user_01",
  "role": "USER",
  "userTrack": "NO",
  "cohort": 4,
  "cohortOrder": 1,
  "publicCode": "#NO401",
  "nickname": "andi",
  "profileImageUrl": "https://images.aandiclub.com/profiles/user_01.png",
  "version": 1
}
```

Delete 시 예시:
- 현재 삭제 이벤트는 발행하지 않습니다.
- 필요하면 `UserDeleted` 같은 별도 이벤트 계약을 추가해야 합니다.

## CI/CD Workflow
- CI (`.github/workflows/ci.yml`)
  - Trigger: `main` 브랜치 `push`, `pull_request`
  - Actions: `./gradlew test`, Docker build check, `docker-compose.yml` 유효성 검사

- CD (`.github/workflows/cd.yml`)
  - Trigger: 태그 `vX.Y.Z` 푸시 (예: `v1.2.3`)
  - Actions: OIDC로 AWS Role Assume -> ECR 이미지 푸시 -> SSH로 EC2 배포

## AWS CD Prerequisites
- GitHub Actions Repository Variables
  - `AWS_REGION`: 예) `ap-northeast-2`
  - `ECR_REPOSITORY`: 예) `aandiclub/auth`
  - `APP_DIR`: EC2 내 compose 배포 경로 (기본 `/opt/auth`)
  - `POSTGRES_DB`: 기본 `auth`
  - `POSTGRES_USER`: 기본 `auth`
  - `APP_CORS_ALLOWED_ORIGINS`: 예) `https://aandiclub.com,https://admin.aandiclub.com,https://auth.aandiclub.com,https://api.aandiclub.com`
  - `JWT_ISSUER`: 예) `https://auth.aandiclub.com`
  - `JWT_AUDIENCE`: 예) `aandiclub-api`
  - `AWS_PORT`: 기본 `22` (옵션)

- GitHub Actions Repository Secrets
  - `AWS_ROLE_TO_ASSUME`: OIDC 신뢰 정책이 설정된 IAM Role ARN
  - `AWS_HOST`: 배포 대상 EC2 호스트
  - `AWS_USER`: SSH 유저
  - `AWS_SSH_KEY`: SSH 개인키
  - `JWT_SECRET`: JWT 서명 키 (32 bytes 이상 강한 랜덤값)
  - `POSTGRES_PASSWORD`: PostgreSQL 비밀번호
  - `REDIS_PASSWORD`: Redis 비밀번호

- EC2 사전 조건
  - Docker + Docker Compose 설치
  - AWS CLI 설치 및 인스턴스 Role에 ECR Pull 권한 부여
