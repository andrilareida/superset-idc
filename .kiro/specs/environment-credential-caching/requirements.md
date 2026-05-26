# Requirements Document

## Introduction

This feature enhances the credential caching mechanism in the DataZone connection mutator. The goal is to provide a robust top-level Redis caching layer that skips the entire token exchange process when cached environment credentials are still valid. The top-level cache check validates credential expiration before initiating any exchange steps, ensuring the full 4-step token chain (Cognito → STS → SSO-OIDC → DataZone) is reliably bypassed when valid credentials exist in Redis.

## Glossary

- **Credential_Cache**: The Redis-based caching system (db=2) that stores environment credentials keyed by user identity and connection parameters.
- **Environment_Credentials**: The final AWS temporary credentials (access key, secret key, session token, expiration) used to connect to Athena/Glue on behalf of a user.
- **Token_Exchange_Chain**: The multi-step credential exchange process (Cognito → STS AssumeRoleWithWebIdentity → SSO-OIDC CreateTokenWithIAM → DataZone RedeemAccessToken → DataZone GetEnvironmentCredentials) that produces Environment_Credentials.
- **TTL_Buffer**: A configurable time buffer (default 60 seconds) subtracted from credential expiration to ensure credentials are refreshed before they actually expire.
- **Cache_Key**: A unique identifier combining the cache step name, user email, and a hash of relevant identifiers (domain ID, environment ID).
- **DataZone_Mutator**: The connection mutator that handles the DataZone IDC credential flow with a 4-step token exchange chain.
- **Top_Level_Cache_Check**: The initial cache lookup performed before any exchange step, including before Cognito token resolution.

## Requirements

### Requirement 1: Top-Level Cache Check Before Any Exchange Step

**User Story:** As a Superset user running frequent queries, I want the DataZone mutator to return cached environment credentials immediately when they are still valid, so that queries complete faster by skipping the entire token exchange chain.

#### Acceptance Criteria

1. WHEN the DataZone_Mutator is invoked for a DataZoneIdc connection, THE DataZone_Mutator SHALL check the Credential_Cache for valid Environment_Credentials as the first operation, before resolving the Cognito ID token or validating environment variables.
2. WHEN the Credential_Cache contains an entry for the Cache_Key, THE DataZone_Mutator SHALL verify the expiration timestamp exceeds the current time plus TTL_Buffer before using the cached credentials.
3. WHEN cached Environment_Credentials pass the expiration validation, THE DataZone_Mutator SHALL use the cached credentials to rewrite the URI and skip all four steps of the Token_Exchange_Chain.
4. IF cached Environment_Credentials have an expiration that does not exceed the current time plus TTL_Buffer, THEN THE DataZone_Mutator SHALL discard the cached entry and proceed with the full Token_Exchange_Chain.
5. THE Top_Level_Cache_Check SHALL use the same Cache_Key format as the existing Step 4 cache (`dz_mutator:env_creds:{user_email}:{identifier_hash}`).

### Requirement 2: Expiration Validation

**User Story:** As a system operator, I want cached credentials to be validated against their expiration time with a safety buffer, so that users are never served credentials that are about to expire or have already expired.

#### Acceptance Criteria

1. THE Credential_Cache SHALL compute the remaining validity of cached credentials as: expiration timestamp minus current time minus TTL_Buffer.
2. WHEN the remaining validity is greater than zero, THE Credential_Cache SHALL consider the credentials valid.
3. WHEN the remaining validity is zero or negative, THE Credential_Cache SHALL consider the credentials expired and return a cache miss.
4. THE Credential_Cache SHALL handle expiration values in multiple formats: Unix timestamp (int or float), ISO 8601 datetime string, and datetime object.
5. IF the expiration value cannot be parsed, THEN THE Credential_Cache SHALL treat the entry as expired and return a cache miss.

### Requirement 3: Cache Storage on Successful Exchange

**User Story:** As a system operator, I want freshly obtained environment credentials to be stored in the cache with an appropriate TTL, so that subsequent requests for the same user and environment can skip the exchange chain.

#### Acceptance Criteria

1. WHEN the Token_Exchange_Chain completes successfully, THE DataZone_Mutator SHALL store the resulting Environment_Credentials in the Credential_Cache.
2. THE Credential_Cache SHALL set the Redis TTL to the credential expiration minus the current time minus TTL_Buffer.
3. WHEN storing credentials, THE Credential_Cache SHALL overwrite any existing entry for the same Cache_Key.
4. IF the computed TTL is zero or negative, THEN THE Credential_Cache SHALL not store the credentials (they are already expired or about to expire).

### Requirement 4: Cache Invalidation on Authentication Failure

**User Story:** As a system operator, I want stale credentials to be automatically invalidated when they cause authentication failures, so that the system self-heals by re-executing the exchange chain.

#### Acceptance Criteria

1. IF a cached credential is used and the downstream AWS API returns an `ExpiredTokenException` or `InvalidCredentialsException`, THEN THE DataZone_Mutator SHALL delete the cache entry for that Cache_Key.
2. WHEN a cache entry is invalidated due to an authentication error, THE DataZone_Mutator SHALL retry the Token_Exchange_Chain once to obtain fresh credentials.
3. IF the retry also fails, THEN THE DataZone_Mutator SHALL return the original URI unchanged (graceful degradation).

### Requirement 5: Cache Observability

**User Story:** As a system operator, I want visibility into cache behavior, so that I can monitor the effectiveness of the caching layer and troubleshoot credential issues.

#### Acceptance Criteria

1. WHEN the Top_Level_Cache_Check returns a hit (valid cached credentials), THE DataZone_Mutator SHALL log at INFO level with the user email, domain ID, environment ID, and remaining TTL.
2. WHEN the Top_Level_Cache_Check returns a miss (no entry or expired entry), THE DataZone_Mutator SHALL log at INFO level indicating a cache miss and that the full exchange chain will execute.
3. WHEN a cache entry is invalidated due to an authentication error, THE DataZone_Mutator SHALL log at WARNING level with the Cache_Key and the error type.
4. WHEN credentials are stored in the cache after a successful exchange, THE DataZone_Mutator SHALL log at INFO level with the Cache_Key and the computed TTL.

### Requirement 6: Graceful Degradation

**User Story:** As a system operator, I want the caching layer to degrade gracefully when Redis is unavailable, so that the mutator continues to function by executing the full exchange chain.

#### Acceptance Criteria

1. IF Redis is unavailable during the Top_Level_Cache_Check, THEN THE DataZone_Mutator SHALL log a warning and proceed with the full Token_Exchange_Chain.
2. IF Redis is unavailable when storing credentials after a successful exchange, THEN THE DataZone_Mutator SHALL log a warning and return the credentials without caching.
3. THE DataZone_Mutator SHALL not raise exceptions to the caller due to Redis failures; all Redis errors are handled internally.

### Requirement 7: Configuration

**User Story:** As a system operator, I want to configure the TTL buffer through an environment variable, so that I can tune the cache safety margin for different deployment scenarios without code changes.

#### Acceptance Criteria

1. THE Credential_Cache SHALL read the TTL_Buffer from the `CREDENTIAL_CACHE_TTL_BUFFER` environment variable (default: 60 seconds).
2. WHEN `CREDENTIAL_CACHE_TTL_BUFFER` is set to a valid integer, THE Credential_Cache SHALL use that value as the buffer in seconds.
3. IF `CREDENTIAL_CACHE_TTL_BUFFER` is set to an invalid value, THEN THE Credential_Cache SHALL fall back to the default of 60 seconds and log a warning.
