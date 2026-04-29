# Requirements: DataZone Connection Mutator

## Requirement 1: Connection Detection and Routing

### User Story
As a Superset administrator, I want the connection mutator to automatically detect Athena connections configured with the DataZone IDC credential provider so that per-user DataZone credentials are injected transparently.

### Acceptance Criteria
1. The mutator intercepts connections with dialect matching `awsathena` (case-insensitive)
2. The mutator only processes connections where `CredentialsProvider=DataZoneIdc` is present in query parameters (case-insensitive match on value)
3. Non-Athena connections are returned unchanged with no side effects
4. Athena connections without `CredentialsProvider=DataZoneIdc` are returned unchanged
5. The mutator extracts DataZone parameters from the connection string: `DataZoneDomainId`, `DataZoneEnvironmentId`, `DataZoneDomainRegion`, `IdentityCenterIssuerUrl`, `Workgroup`
6. Missing connection string parameters fall back to environment variables: `DATAZONE_DOMAIN_ID`, `DATAZONE_ENVIRONMENT_ID`, `AWS_REGION`
7. If required parameters (`domain_id`, `environment_id`) are missing from both connection string and environment variables, the mutator logs an error and returns the URI unchanged

---

## Requirement 2: User Context Resolution

### User Story
As a Superset user, I want the mutator to resolve my identity from either the web session or the background worker context so that my DataZone credentials are used regardless of how the query is executed.

### Acceptance Criteria
1. In Flask web request context, the user email is resolved from `flask_login.current_user.email`
2. In Celery worker context (no Flask session), the user email is resolved from `flask.g.user.email`
3. If no authenticated user can be resolved, the mutator logs a warning and returns the URI unchanged
4. Anonymous users are never processed (treated as "no user")

---

## Requirement 3: Cognito Token Management

### User Story
As a Superset user, I want my Cognito ID token to be available for the DataZone credential exchange whether I'm in a web session or a background task.

### Acceptance Criteria
1. In web context, the Cognito ID token is read from `flask.session["cognito_id_token"]`
2. In worker context, the Cognito ID token is read from Redis (keyed by user email, stored by the security manager at login)
3. If the token is expired (checked via JWT `exp` claim with 60-second buffer), a refresh is attempted using the stored refresh token
4. Token refresh uses Cognito `InitiateAuth` with `REFRESH_TOKEN_AUTH` flow
5. After successful refresh, the new token is stored in both Flask session (if available) and Redis
6. If no token is available and refresh is not possible, the mutator logs a warning and returns the URI unchanged

---

## Requirement 4: Token Exchange Chain - Step 1 (AssumeRoleWithWebIdentity)

### User Story
As the system, I need to exchange the Cognito ID token for intermediary IAM credentials so that I can call the SSO-OIDC API on behalf of the user.

### Acceptance Criteria
1. Calls STS `AssumeRoleWithWebIdentity` with the Cognito ID token as `WebIdentityToken`
2. Uses `OIDC_ROLE_ARN` environment variable as the `RoleArn`
3. Sets `RoleSessionName` to a sanitized form of the user email (max 64 chars, valid characters only)
4. Sets `DurationSeconds=900` (15 minutes — minimum needed for the subsequent steps)
5. Returns the temporary credentials (`AccessKeyId`, `SecretAccessKey`, `SessionToken`)
6. On failure (e.g., trust policy mismatch), raises `RuntimeError` with the STS error code and role ARN for debugging

---

## Requirement 5: Token Exchange Chain - Step 2 (CreateTokenWithIAM)

### User Story
As the system, I need to exchange the Cognito token for an Identity Center access token so that I can authenticate with DataZone.

### Acceptance Criteria
1. Creates a boto3 session using the intermediary credentials from Step 1
2. Calls SSO-OIDC `CreateTokenWithIAM` with:
   - `clientId` = `IDC_APPLICATION_ARN` environment variable
   - `grantType` = `"urn:ietf:params:oauth:grant-type:jwt-bearer"`
   - `assertion` = the Cognito ID token
3. Extracts the `accessToken` from the response
4. Records the `expiresIn` value for cache TTL calculation
5. On `InvalidGrantException`, logs the Cognito token's `iss`, `aud`, and `exp` claims for debugging
6. On failure, raises `RuntimeError` with the error code and IDC application ARN

---

## Requirement 6: Token Exchange Chain - Step 3 (RedeemAccessToken)

### User Story
As the system, I need to redeem the IDC access token with DataZone to obtain DomainExecutionRole credentials.

### Acceptance Criteria
1. Sends an HTTP POST to `https://datazone.{region}.api.aws/sso/redeem-token`
2. Request body is JSON: `{"domainId": "<domain_id>", "accessToken": "<idc_access_token>"}`
3. Request includes `Content-Type: application/json` header
4. The region is taken from the parsed connection parameters (`DataZoneDomainRegion`)
5. On success (HTTP 200), extracts credentials from `response["credentials"]`: `accessKeyId`, `secretAccessKey`, `sessionToken`, `expiration`
6. On HTTP error (non-2xx), raises `RuntimeError` with the status code and response body
7. On network/connection error, raises `RuntimeError` with connection details

---

## Requirement 7: Token Exchange Chain - Step 4 (GetEnvironmentCredentials)

### User Story
As the system, I need to use the DomainExecutionRole credentials to obtain the final environment-scoped credentials for Athena/Glue access.

### Acceptance Criteria
1. Creates a boto3 session using the DomainExecutionRole credentials from Step 3
2. Creates a DataZone client in the appropriate region
3. Calls `get_environment_credentials` with:
   - `domainIdentifier` = the DataZone domain ID
   - `environmentIdentifier` = the DataZone environment ID
4. Extracts `accessKeyId`, `secretAccessKey`, `sessionToken`, and `expiration` from the response
5. On `AccessDeniedException`, raises `RuntimeError` indicating the user may not be a project member
6. On other failures, raises `RuntimeError` with the error details

---

## Requirement 8: Redis Caching Strategy

### User Story
As a Superset administrator, I want intermediate and final credentials cached in Redis so that repeated queries don't trigger the full token exchange chain every time.

### Acceptance Criteria
1. Each step's output is cached in Redis with a unique key per user and step: `dz_mutator:{step}:{user_email}:{identifier}`
2. Intermediary role credentials (Step 1) are cached with TTL = 850 seconds (900s duration - 50s buffer)
3. IDC access token (Step 2) is cached with TTL = `expiresIn - 60` seconds
4. Domain execution credentials (Step 3) are cached with TTL = `expiration - current_time - 60` seconds
5. Environment credentials (Step 4) are cached with TTL = `expiration - current_time - 60` seconds
6. On cache hit, the cached value is returned without making the corresponding API call
7. On cache miss or expired entry, the API call is made and the result is cached
8. Cache uses Redis DB 2 (separate from session store DB 0 and TIP cache DB 1)
9. All cached values are JSON-serialized

---

## Requirement 9: URI Rewriting

### User Story
As a Superset user, I want the connection URI to be transparently rewritten with my DataZone credentials so that PyAthena can connect on my behalf.

### Acceptance Criteria
1. The rewritten URI uses the environment credentials: `username=access_key_id`, `password=secret_access_key`
2. The `aws_session_token` is added as a query parameter
3. Non-credential query parameters from the original URI are preserved (e.g., `work_group`, `region_name`, `catalog_name`)
4. Credential-related parameters are removed from the query string: `CredentialsProvider`, `DataZoneDomainId`, `DataZoneEnvironmentId`, `DataZoneDomainRegion`, `IdentityCenterIssuerUrl`
5. The original URI object is never mutated; a new `SqlaURL` is created
6. The `drivername`, `host`, `port`, and `database` from the original URI are preserved

---

## Requirement 10: Error Handling and Graceful Degradation

### User Story
As a Superset administrator, I want the mutator to fail gracefully with clear error messages so that I can diagnose configuration issues without breaking the application.

### Acceptance Criteria
1. If any step in the token chain raises an exception, the mutator catches it, logs the error with context (step name, user, relevant ARNs), and returns the original URI unchanged
2. Missing environment variables (`OIDC_ROLE_ARN`, `IDC_APPLICATION_ARN`) cause a clear error message identifying which variable is missing
3. If Redis is unavailable, the mutator proceeds without caching (executes the full chain on every request) and logs a warning
4. Logged error messages include enough context to diagnose the issue (role ARNs, domain IDs, error codes) but never include secret keys or tokens
5. The mutator never raises an unhandled exception to Superset — all errors are caught and result in returning the original URI

---

## Requirement 11: Security and Credential Isolation

### User Story
As a security-conscious administrator, I want credentials to be properly isolated per user and never exposed in logs.

### Acceptance Criteria
1. Redis cache keys include the user email, ensuring no cross-user credential leakage
2. Log messages redact `aws_secret_access_key` and `aws_session_token` values (replace with `***`)
3. The rewritten URI logged for debugging masks the password and session token
4. The Cognito client secret is never logged
5. Redis DB 2 is used exclusively for DataZone mutator cache (isolation from other Redis users)

---

## Requirement 12: Dual Context Support (Web and Worker)

### User Story
As a Superset user, I want my DataZone-connected queries to work both when I run them interactively and when they execute as scheduled/background tasks.

### Acceptance Criteria
1. In web request context (Flask session available), Cognito tokens are read from the session
2. In Celery worker context (no Flask session), Cognito tokens are read from Redis (stored at login by the security manager)
3. The security manager's `oauth_user_info` method stores Cognito tokens in Redis at login time (reuses existing `_store_cognito_tokens_in_redis` pattern)
4. The mutator produces identical results regardless of execution context (web vs worker) given the same user and connection parameters
