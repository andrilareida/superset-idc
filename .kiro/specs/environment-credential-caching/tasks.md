# Implementation Plan: Environment Credential Caching

## Overview

Add a top-level Redis caching layer to the DataZone connection mutator that checks for valid cached environment credentials **before** initiating any token exchange steps (including Cognito token resolution). This includes expiration validation with a configurable TTL buffer, cache invalidation on authentication failures, retry-once logic, and observability logging.

All changes target `docker/pythonpath_dev/datazone_connection_mutator.py` with tests in a new test file alongside it.

## Tasks

- [x] 1. Implement TTL buffer configuration helper
  - [x] 1.1 Add `_get_ttl_buffer()` function
    - Read `CREDENTIAL_CACHE_TTL_BUFFER` environment variable
    - Return integer value if valid, default to 60 if unset or invalid
    - Log a WARNING if the value is set but not a valid integer
    - _Requirements: 7.1, 7.2, 7.3_

  - [x] 1.2 Write property test for TTL buffer configuration (Property 5)
    - **Property 5: Valid integer environment variable is used as buffer**
    - Generate random integer strings and non-integer strings via Hypothesis
    - Verify valid integers return that value, non-integers return 60
    - **Validates: Requirements 7.2, 7.3**

  - [x] 1.3 Update `_compute_expiration_ttl` to accept optional buffer parameter
    - Add `buffer: int | None = None` parameter
    - Default to `_get_ttl_buffer()` when buffer is None
    - Replace hardcoded `60` with the buffer parameter
    - _Requirements: 2.1, 7.1_

- [x] 2. Implement credential expiration validation
  - [x] 2.1 Add `_is_credential_expired()` function
    - Accept `cached_entry: dict[str, Any]` and `ttl_buffer: int` parameters
    - Parse the `expiration` field (Unix timestamp int/float, ISO 8601 string, datetime object)
    - Return `True` if `expiration_epoch - current_time - ttl_buffer <= 0`
    - Return `True` if expiration cannot be parsed (treat as expired)
    - Log at DEBUG level if expiration is unparseable
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5_

  - [x] 2.2 Write property test for expiration validity (Property 1)
    - **Property 1: Expiration validity is determined by the formula (expiration - now - buffer)**
    - Generate random timestamps and buffer values
    - Verify credentials are valid iff `expiration_epoch - current_time - buffer > 0`
    - **Validates: Requirements 1.2, 2.1, 2.2, 2.3, 3.2**

  - [x] 2.3 Write property test for expiration format equivalence (Property 2)
    - **Property 2: Expiration format equivalence**
    - Generate random future timestamps, express as int, float, ISO string, and datetime
    - Verify all formats produce the same validity determination (within 1s tolerance)
    - **Validates: Requirements 2.4**

- [x] 3. Implement cache invalidation helper
  - [x] 3.1 Add `_invalidate_cache_entry()` function
    - Accept `cache_key: str` parameter
    - Delete the key from Redis using `_dz_redis.delete(cache_key)`
    - Wrap in try/except to catch all Redis exceptions
    - Log at WARNING level on Redis errors, return without raising
    - Log at INFO level on successful invalidation
    - _Requirements: 4.1, 6.3_

  - [x] 3.2 Write property test for Redis error containment (Property 4)
    - **Property 4: Redis errors never propagate to the caller**
    - Generate various Redis exception types (ConnectionError, TimeoutError, RedisError)
    - Mock `_dz_redis` to raise these exceptions during get/set/delete
    - Verify no exception propagates from `_cache_get`, `_cache_set`, `_invalidate_cache_entry`
    - **Validates: Requirements 6.3**

- [x] 4. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 5. Restructure mutator entry point with top-level cache check
  - [x] 5.1 Add top-level cache check before Cognito token resolution
    - After parsing DataZone params and resolving user email, build the final cache key using `_build_cache_key("env_creds", user_email, domain_id, environment_id)`
    - Call `_cache_get(cache_key)` to check for cached credentials
    - If hit, validate expiration using `_is_credential_expired(cached_entry, _get_ttl_buffer())`
    - If valid: rewrite URI with cached credentials and return immediately (skip entire chain)
    - If expired or miss: proceed with Cognito resolution and full chain
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5_

  - [x] 5.2 Write property test for cache key consistency (Property 3)
    - **Property 3: Cache key consistency between top-level check and Step 4**
    - Generate random user emails, domain IDs, and environment IDs
    - Verify the cache key from the top-level check equals the key from `_get_environment_credentials`
    - **Validates: Requirements 1.5**

  - [x] 5.3 Add observability logging for cache hits and misses
    - On cache hit (valid): log at INFO level with user email, domain ID, environment ID, remaining TTL
    - On cache miss or expired: log at INFO level indicating miss and that full chain will execute
    - On Redis error during check: log at WARNING level and proceed with chain
    - _Requirements: 5.1, 5.2, 6.1_

  - [x] 5.4 Write unit tests for top-level cache check behavior
    - Test cache hit with valid credentials skips entire chain (mock ordering verification)
    - Test cache miss triggers full chain execution
    - Test expired cached entry triggers full chain execution
    - Test Redis unavailability logs warning and proceeds with chain
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 6.1_

- [x] 6. Implement retry-once logic on authentication failure
  - [x] 6.1 Add retry logic after cache invalidation
    - When the token exchange chain raises `ExpiredTokenException` or `InvalidCredentialsException` from cached credentials, call `_invalidate_cache_entry(cache_key)`
    - Retry the full token exchange chain once
    - If retry succeeds: cache new credentials and rewrite URI
    - If retry fails: return original URI unchanged (graceful degradation)
    - Log at WARNING level on invalidation with cache key and error type
    - _Requirements: 4.1, 4.2, 4.3, 5.3_

  - [x] 6.2 Write unit tests for retry logic
    - Test invalidation + successful retry returns new credentials
    - Test invalidation + failed retry returns original URI
    - Test WARNING log emitted on invalidation
    - _Requirements: 4.1, 4.2, 4.3, 5.3_

- [ ] 7. Add cache storage observability logging
  - [x] 7.1 Add INFO log on successful credential storage
    - After storing credentials in cache (post-chain), log at INFO with cache key and computed TTL
    - _Requirements: 5.4, 3.1, 3.2_

  - [x] 7.2 Write unit tests for observability logging
    - Verify INFO log on cache hit contains user email, domain ID, environment ID, TTL
    - Verify INFO log on cache miss indicates full chain execution
    - Verify WARNING log on invalidation contains cache key and error type
    - Verify INFO log on credential storage contains cache key and TTL
    - _Requirements: 5.1, 5.2, 5.3, 5.4_

- [x] 8. Final checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- All changes target `docker/pythonpath_dev/datazone_connection_mutator.py`
- Tests use `pytest` + `hypothesis` (already in project) with `fakeredis` for Redis mocking
- Property tests use `@settings(max_examples=100)` minimum
- Use `time_machine` or `freezegun` for deterministic time-based tests
- Mock `boto3` clients and `requests` — no real AWS calls in tests
- Each property test references a specific correctness property from the design document
