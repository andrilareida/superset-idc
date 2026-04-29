# Tasks: DataZone Connection Mutator

## Task 1: Create module skeleton and connection detection

- [x] 1.1 Create `docker/pythonpath_dev/datazone_connection_mutator.py` with module docstring, imports, and environment variable loading (OIDC_ROLE_ARN, IDC_APPLICATION_ARN, DATAZONE_DOMAIN_ID, DATAZONE_ENVIRONMENT_ID, AWS_REGION, REDIS_HOST, REDIS_PORT)
- [x] 1.2 Implement `parse_datazone_params(uri)` function that extracts DataZone parameters from the connection string query params, with fallback to environment variables
- [x] 1.3 Implement the `datazone_connection_mutator()` hook entry point with dialect detection (`awsathena`), `CredentialsProvider=DataZoneIdc` check, and early returns for non-matching connections
- [x] 1.4 Implement `_get_current_user_email()` helper (reuse pattern from existing mutator: Flask current_user → g.user fallback)

## Task 2: Cognito token retrieval and refresh

- [x] 2.1 Initialize module-level Redis client (db=2) for DataZone credential caching
- [x] 2.2 Implement `_get_cognito_id_token(user_email)` that reads from Flask session first, then falls back to Redis (reuse existing `_get_cognito_tokens_from_redis` from the TIP mutator or import it)
- [x] 2.3 Implement token expiry checking with 60-second buffer (reuse `_is_token_expired` pattern)
- [x] 2.4 Implement Cognito token refresh via `_refresh_cognito_id_token()` (reuse existing implementation or import from TIP mutator)

## Task 3: Token exchange chain - Steps 1 & 2

- [x] 3.1 Implement `_assume_role_with_web_identity(cognito_id_token, oidc_role_arn, user_email)` — calls STS AssumeRoleWithWebIdentity with DurationSeconds=900
- [x] 3.2 Implement `_create_token_with_iam(cognito_id_token, intermediary_creds, idc_application_arn)` — creates boto3 session from intermediary creds, calls SSO-OIDC CreateTokenWithIAM, returns access_token and expires_in
- [x] 3.3 Add error handling for Step 1 (log role ARN, token issuer on failure) and Step 2 (log IDC app ARN, Cognito claims on InvalidGrantException)

## Task 4: Token exchange chain - Steps 3 & 4

- [x] 4.1 Implement `_redeem_access_token(idc_access_token, domain_id, region)` — HTTP POST to `https://datazone.{region}.api.aws/sso/redeem-token`, returns DomainExecutionRole credentials
- [x] 4.2 Implement `_get_environment_credentials(domain_creds, domain_id, environment_id, region)` — creates boto3 session from domain creds, calls DataZone GetEnvironmentCredentials
- [x] 4.3 Add error handling for Step 3 (HTTP status codes, response body) and Step 4 (AccessDeniedException with project membership hint)

## Task 5: Redis caching layer

- [x] 5.1 Implement `_cache_get(cache_key)` and `_cache_set(cache_key, value, ttl_seconds)` helpers with JSON serialization and Redis error handling (graceful degradation)
- [x] 5.2 Implement cache key generation: `dz_mutator:{step}:{user_email}:{identifier_hash}`
- [x] 5.3 Add caching to Step 1 (intermediary creds, TTL=850s)
- [x] 5.4 Add caching to Step 2 (IDC access token, TTL=expiresIn-60s)
- [x] 5.5 Add caching to Step 3 (domain execution creds, TTL based on expiration-60s)
- [x] 5.6 Add caching to Step 4 (environment creds, TTL based on expiration-60s)

## Task 6: URI rewriting and orchestration

- [x] 6.1 Implement `_build_datazone_url(uri, creds, dz_params)` — creates new SqlaURL with credentials as username/password, session_token in query, preserves non-credential params, removes DataZone-specific params
- [x] 6.2 Implement the full orchestration in `datazone_connection_mutator()`: get user → get token → check final cache → execute chain steps (with per-step caching) → rewrite URI
- [x] 6.3 Add credential scrubbing to all log messages (mask secret_access_key and session_token)
- [x] 6.4 Add top-level try/except in the mutator entry point to catch all exceptions and return original URI unchanged

## Task 7: Integration with Superset configuration

- [x] 7.1 Update `docker/.env-local` to add `OIDC_ROLE_ARN` environment variable (using the existing `AndriSupersetPoc` role ARN)
- [x] 7.2 Document how to register the mutator in `superset_config.py` (either as the sole mutator or chained with the existing TIP mutator)
- [x] 7.3 Add a composite mutator function that routes to either TIP or DataZone mutator based on connection string parameters (if both need to coexist)

## Task 8: Unit tests

- [x] 8.1 Create `docker/pythonpath_dev/tests/test_datazone_connection_mutator.py` with test fixtures (mock Redis, mock boto3 clients, sample URIs)
- [x] 8.2 Write tests for `parse_datazone_params()` — valid DataZoneIdc URIs, non-DataZoneIdc URIs, missing params with env var fallback
- [x] 8.3 Write tests for the full token chain (all cache misses) with mocked AWS responses
- [x] 8.4 Write tests for cache hit scenarios (no API calls made when cache is populated)
- [x] 8.5 Write tests for error handling — each step failure returns original URI unchanged
- [x] 8.6 Write tests for user isolation — different users get different cache keys
- [x] 8.7 Write tests for Redis unavailability — mutator still works without caching
