# Implementation Plan: Athena Identity Propagation

## Overview

Migrate the existing session-tag-based Athena credential flow to AWS Trusted Identity Propagation (TIP). The work touches three existing files and adds a new test directory. Each task builds on the previous, ending with full wiring and test coverage.

## Tasks

- [x] 1. Add Cognito ID token storage to CognitoSecurityManager
  - [x] 1.1 Store `id_token` in Flask session inside `oauth_user_info`
    - In `docker/pythonpath_dev/custom_sso_security_manager.py`, import `flask.session` and add `flask_session["cognito_id_token"] = response["id_token"]` before returning the user info dict, guarded by `if response and response.get("id_token")`
    - _Requirements: 3.2_

  - [ ]* 1.2 Write unit tests for ID token storage and OIDC claim extraction
    - Create `tests/unit_tests/docker/pythonpath_dev/test_custom_sso_security_manager.py`
    - Test: ID token is stored in Flask session after successful login
    - Test: ID token is not stored when response is None or missing `id_token`
    - Test: `email` and `sub` are correctly extracted from OIDC claims
    - Test: groups from userinfo response are mapped to the correct role
    - Test: groups from ID token fallback (JWT decode) are mapped correctly
    - Test: first matching group wins when multiple groups match
    - Test: no matching group falls back to `"Gamma"`
    - Test: JWT decode failure logs a warning and falls back to default role
    - _Requirements: 1.3, 2.1, 2.2, 2.3, 2.4_

- [x] 2. Rewrite `athena_connection_mutator.py` with TIP token exchange flow
  - [x] 2.1 Add `_IDC_APPLICATION_ARN` env var and `_get_cognito_id_token` helper
    - Add `_IDC_APPLICATION_ARN = os.environ.get("IDC_APPLICATION_ARN", "")` alongside the existing env var reads
    - Add `_get_cognito_id_token() -> str | None` that reads `flask.session.get("cognito_id_token")`
    - _Requirements: 6.2, 3.2_

  - [x] 2.2 Replace `_assume_role_for_user` with `_exchange_token_with_idc` and `_assume_role_with_idc_context`
    - Delete the existing `_assume_role_for_user` function (which uses session tags)
    - Add `_exchange_token_with_idc(id_token: str) -> str` that calls `sso-oidc:CreateTokenWithIAM` with `grantType="urn:ietf:params:oauth:grant-type:jwt-bearer"` and `assertion=id_token`; raises `ValueError` if `_IDC_APPLICATION_ARN` is empty; raises `RuntimeError` (with `logger.exception`) on `BotoCoreError`/`ClientError`
    - Add `_assume_role_with_idc_context(user_email: str, idc_token: str) -> dict[str, str]` that calls `sts:AssumeRole` with `ProvidedContexts=[{"ProviderArn": "arn:aws:iam::aws:contextProvider/IdentityCenter", "ContextAssertion": idc_token}]` and `DurationSeconds=3600`; raises `ValueError` if `_EXECUTION_ROLE_ARN` is empty; raises `RuntimeError` (with `logger.exception`) on `BotoCoreError`/`ClientError`
    - _Requirements: 3.3, 3.4, 6.1, 6.2, 6.3, 6.4, 6.5, 8.1, 8.3_

  - [x] 2.3 Update `athena_db_connection_mutator` to use the TIP flow
    - Replace the call to `_assume_role_for_user` with: (1) call `_get_cognito_id_token()`; if `None`, log warning and return original URI (Req 6.6); (2) call `_exchange_token_with_idc(id_token)`; (3) call `_assume_role_with_idc_context(user_email, idc_token)`
    - Keep the existing URI rewrite logic (URL-encoding, non-credential param preservation) unchanged
    - _Requirements: 3.1, 3.5, 3.6, 3.7, 5.1, 5.2, 5.3, 6.6_

  - [ ]* 2.4 Write unit tests for the TIP mutator
    - Create `tests/unit_tests/docker/pythonpath_dev/test_athena_connection_mutator.py`
    - Test: non-Athena URI is returned unchanged
    - Test: anonymous user returns original URI unchanged
    - Test: missing Cognito ID token in session falls back to ambient credentials (returns original URI)
    - Test: missing `ATHENA_EXECUTION_ROLE_ARN` raises `ValueError`
    - Test: missing `IDC_APPLICATION_ARN` raises `ValueError`
    - Test: `CreateTokenWithIAM` `BotoCoreError` raises `RuntimeError` with user email in message
    - Test: STS `AssumeRole` `ClientError` raises `RuntimeError` with user email in message
    - Test: successful TIP flow rewrites URI with credentials (mock SSO-OIDC + STS)
    - Test: `CreateTokenWithIAM` is called with correct `grantType` and `assertion`
    - Test: `AssumeRole` is called with `ProvidedContexts` (not `Tags`/`TransitiveTagKeys`)
    - Test: non-credential query params (e.g. `?schema=mydb`) are preserved in rewritten URI
    - Test: credential params in original URI are stripped from rewritten URI
    - Test: all credential values in rewritten URI are URL-encoded
    - _Requirements: 3.1, 3.3, 3.4, 3.5, 3.6, 3.7, 4.1, 4.2, 4.3, 5.1, 5.2, 5.3, 6.1, 6.2, 6.3, 6.4, 6.5, 6.6_

- [x] 3. Checkpoint — Ensure all unit tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 4. Write Hypothesis property-based tests
  - Create `tests/unit_tests/docker/pythonpath_dev/__init__.py` (empty, for pytest discovery)
  - Create `tests/unit_tests/docker/pythonpath_dev/test_properties.py`

  - [ ]* 4.1 Property 1 — Session name sanitization produces only allowed characters and is ≤ 64 chars
    - `@given(st.text())` over arbitrary email strings
    - Assert `len(result) <= 64` and `re.fullmatch(r"[a-zA-Z0-9+=,.@_\-]*", result)`
    - **Property 1: Session name sanitization strips disallowed characters**
    - **Validates: Requirements 4.2, 4.3**

  - [ ]* 4.2 Property 2 — Session name sanitization is idempotent
    - `@given(st.text(alphabet=..., max_size=64))` over already-safe strings
    - Assert applying sanitization twice equals applying it once
    - **Property 2: Session name sanitization is idempotent**
    - **Validates: Requirements 4.2, 4.3**

  - [ ]* 4.3 Property 3 — Non-Athena URIs pass through unchanged
    - `@given(st.text().filter(lambda s: "awsathena" not in s.lower()))`
    - Assert returned URI and connect_args are identical to inputs
    - **Property 3: Non-Athena URIs pass through unchanged**
    - **Validates: Requirements 5.3**

  - [ ]* 4.4 Property 4 — Unauthenticated connections pass through unchanged
    - `@given(st.text(min_size=1).map(lambda s: "awsathena+rest://" + s))` with anonymous `current_user` mocked
    - Assert returned URI equals input URI
    - **Property 4: Unauthenticated connections pass through unchanged**
    - **Validates: Requirements 5.1, 5.2**

  - [ ]* 4.5 Property 5 — Non-credential query params are preserved in rewritten URI
    - `@given(st.fixed_dictionaries({"schema": ..., "catalog": ...}))` with mocked SSO-OIDC + STS
    - Assert all extra params survive the rewrite and original credential params are absent
    - **Property 5: Rewritten URI preserves non-credential query parameters**
    - **Validates: Requirements 3.7**

  - [ ]* 4.6 Property 6 — Rewritten URI contains all required credential components URL-encoded
    - `@given(st.fixed_dictionaries({"AccessKeyId": ..., "SecretAccessKey": ..., "SessionToken": ...}))` with mocked SSO-OIDC + STS
    - Assert `aws_access_key_id`, `aws_secret_access_key`, `aws_session_token`, and `s3_staging_dir` are present and URL-encoded in the rewritten URI
    - **Property 6: Rewritten URI contains all required credential components URL-encoded**
    - **Validates: Requirements 3.5, 3.6**

  - [ ]* 4.7 Property 7 — Group-to-role mapping is deterministic
    - `@given(st.lists(st.text()))` over arbitrary group lists
    - Assert calling the mapping logic twice with the same input yields the same role
    - **Property 7: Group-to-role mapping is deterministic**
    - **Validates: Requirements 2.3, 2.4**

  - [ ]* 4.8 Property 8 — TIP token exchange flow is invoked for authenticated Athena connections
    - `@given(st.text(...).map(lambda s: s + "@example.com"))` with mocked `current_user`, Flask session, SSO-OIDC, and STS
    - Assert `CreateTokenWithIAM` is called with `assertion=id_token` and `AssumeRole` is called with `ProvidedContexts` (not `Tags`)
    - **Property 8: TIP token exchange flow is invoked for authenticated Athena connections**
    - **Validates: Requirements 3.3, 3.4, 8.3**

  - [ ]* 4.9 Property 9 — OIDC claim extraction works for all valid token shapes
    - `@given(st.fixed_dictionaries({"email": st.emails(), "sub": st.uuids().map(str), "given_name": ..., "family_name": ...}))` with mocked userinfo endpoint
    - Assert returned dict has non-empty `username`, `email`, and `id` matching the input claims
    - **Property 9: OIDC claim extraction works for all valid token shapes**
    - **Validates: Requirements 1.3**

- [x] 5. Update `superset_config_docker.py` to add `IDC_APPLICATION_ARN` documentation
  - Add a comment in the env var documentation block noting `IDC_APPLICATION_ARN` as a required variable for the TIP flow
  - _Requirements: 7.4, 7.7_

- [x] 6. Update `docker-compose.yml` to pass `IDC_APPLICATION_ARN` env var
  - Add `IDC_APPLICATION_ARN: ${IDC_APPLICATION_ARN:-}` to the `environment` block of the `superset`, `superset-init`, and `superset-worker` services
  - _Requirements: 7.2, 7.7_

- [x] 7. Final checkpoint — Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for a faster MVP
- The `tests/unit_tests/docker/` and `tests/unit_tests/docker/pythonpath_dev/` directories need `__init__.py` files for pytest discovery
- All property tests use `@settings(max_examples=100)` and the tag comment `# Feature: athena-identity-propagation, Property N: <text>`
- The existing `docker-compose.yml` already mounts `~/.aws` and passes `COGNITO_CLIENT_ID`/`COGNITO_CLIENT_SECRET` — only `IDC_APPLICATION_ARN` needs to be added
- `requirements-local.txt` already contains `PyAthena[SQLAlchemy]>=3.0.0` — no change needed
- `superset_config_docker.py` already wires `CUSTOM_SECURITY_MANAGER`, `AUTH_TYPE`, and `DB_CONNECTION_MUTATOR` — no structural changes needed, only a comment update
