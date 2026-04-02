# Design Document: Athena Identity Propagation

## Overview

This feature enables Apache Superset to authenticate users via Amazon Cognito (OIDC) and propagate each user's identity to Amazon Athena queries through AWS IAM Identity Center's Trusted Identity Propagation (TIP). When a Superset user runs a query against an Athena database connection, the system performs a two-step token exchange: first, the user's Cognito ID token is exchanged for an Identity Center token via the `sso-oidc:CreateTokenWithIAM` API; then, that Identity Center token is passed to `sts:AssumeRole` via the `ProvidedContexts` parameter to obtain temporary credentials that carry the user's Identity Center identity. This allows Lake Formation and Athena to enforce row-level and column-level security policies scoped to the individual user — without session tags.

The implementation lives entirely in `docker/pythonpath_dev/` — the Docker-based development environment overlay — and consists of three files:

1. `custom_sso_security_manager.py` — `CognitoSecurityManager`, a Flask-AppBuilder `SecurityManager` subclass that maps Cognito OIDC claims and group memberships to Superset user attributes and roles, and stores the Cognito ID token in the Flask session for later use by the Connection_Mutator.
2. `athena_connection_mutator.py` — `athena_db_connection_mutator`, a `DB_CONNECTION_MUTATOR` hook that intercepts Athena database connections, performs the Identity Center token exchange, and rewrites the SQLAlchemy URI with per-user STS temporary credentials.
3. `superset_config_docker.py` — Superset configuration that wires the two components above into the application and configures the Cognito OIDC provider.

Supporting infrastructure: `docker-compose.yml` mounts host AWS credentials and passes Cognito environment variables; `requirements-local.txt` adds the `PyAthena[SQLAlchemy]` driver.

### Key Design Decisions

- **No core Superset changes**: All logic lives in the Docker overlay (`docker/pythonpath_dev/`), keeping the feature self-contained and upgrade-safe.
- **Trusted Identity Propagation (TIP) instead of session tags**: Rather than using STS session tags for ABAC, the user's Cognito ID token is exchanged for an Identity Center token via `sso-oidc:CreateTokenWithIAM`. The Identity Center token is then passed to `sts:AssumeRole` via `ProvidedContexts`, allowing Lake Formation to resolve the user's identity directly from Identity Center. This is the AWS-recommended approach for propagating end-user identity to analytics services.
- **Two-step token exchange**: The flow is Cognito ID token → Identity Center token (via `CreateTokenWithIAM`) → STS credentials with `ProvidedContexts`. This requires an Identity Center application with a Trusted Token Issuer configured to trust the Cognito User Pool.
- **ID token stored in Flask session**: The `CognitoSecurityManager` stores the raw Cognito ID token in the Flask session so the Connection_Mutator can access it at query time for the token exchange. This avoids re-authenticating the user on every query.
- **Ambient credential fallback**: Unauthenticated connections (background tasks, health checks) or connections where the ID token is unavailable fall back to the process's ambient AWS credentials rather than failing, preserving operational stability.
- **JWT decode without re-verification**: Cognito's `cognito:groups` claim is not always present in the userinfo endpoint response. The ID token is decoded without signature verification (Authlib has already validated it) to extract groups — a deliberate trade-off between correctness and simplicity.

---

## Architecture

```mermaid
sequenceDiagram
    participant Browser
    participant Superset
    participant Cognito
    participant SSO_OIDC as Identity Center (SSO-OIDC)
    participant STS
    participant Athena
    participant LakeFormation

    Browser->>Superset: GET /login
    Superset->>Browser: Redirect to Cognito Hosted UI
    Browser->>Cognito: Authenticate (username + password / MFA)
    Cognito->>Browser: Authorization code → redirect to /oauth-authorized/cognito
    Browser->>Superset: GET /oauth-authorized/cognito?code=...
    Superset->>Cognito: Exchange code for tokens (access_token, id_token)
    Cognito->>Superset: Tokens
    Superset->>Superset: CognitoSecurityManager.oauth_user_info()<br/>Extract email, name, groups → assign role<br/>Store id_token in Flask session
    Superset->>Browser: Session cookie (authenticated)

    Browser->>Superset: Run Athena query
    Superset->>Superset: DB_CONNECTION_MUTATOR hook<br/>athena_db_connection_mutator()
    Superset->>SSO_OIDC: CreateTokenWithIAM(<br/>  grant_type=jwt-bearer,<br/>  assertion=cognito_id_token)
    SSO_OIDC->>Superset: Identity Center token (idcToken, context)
    Superset->>STS: AssumeRole(RoleArn,<br/>  SessionName=email,<br/>  ProvidedContexts=[{ProviderArn, ContextAssertion}])
    STS->>Superset: Temporary credentials (key, secret, token)
    Superset->>Athena: Query with temporary credentials
    Athena->>LakeFormation: Authorize (Identity Center user identity)
    LakeFormation->>Athena: Filtered result set
    Athena->>Superset: Query results
    Superset->>Browser: Chart / table data
```

### Component Interaction

```mermaid
graph TD
    A[superset_config_docker.py] -->|CUSTOM_SECURITY_MANAGER| B[CognitoSecurityManager]
    A -->|DB_CONNECTION_MUTATOR| C[athena_db_connection_mutator]
    A -->|OAUTH_PROVIDERS| D[Cognito OIDC Provider]
    B -->|extends| E[SupersetSecurityManager]
    B -->|calls| D
    B -->|stores id_token in| S[Flask Session]
    C -->|reads id_token from| S
    C -->|reads| F[flask_login.current_user]
    C -->|calls| SSO[boto3 SSO-OIDC client]
    SSO -->|CreateTokenWithIAM| IDC[Identity Center]
    C -->|calls| G[boto3 STS client]
    G -->|AssumeRole + ProvidedContexts| H[IAM Execution Role]
    H -->|Identity Center identity| I[Lake Formation TIP]
    J[docker-compose.yml] -->|mounts ~/.aws| G
    J -->|env vars| A
```

---

## Components and Interfaces

### 1. CognitoSecurityManager (`custom_sso_security_manager.py`)

Extends `superset.security.SupersetSecurityManager` (which extends Flask-AppBuilder's `SecurityManager`).

**Overridden method:**

```python
def oauth_user_info(
    self, provider: str, response: dict | None = None
) -> dict[str, str]:
```

Called by Flask-AppBuilder's OAuth flow after token exchange. Returns a dict with keys:
- `username` — user's email (used as the Superset username)
- `email` — user's email address
- `first_name`, `last_name` — from `given_name`/`family_name` OIDC claims
- `id` — Cognito `sub` claim
- `name` — display name
- `role_keys` — list containing the single resolved Superset role name

**ID token storage:**
The method stores the raw Cognito ID token in the Flask session (`session["cognito_id_token"]`) so that the Connection_Mutator can access it at query time for the Identity Center token exchange. This is done before returning the user info dict.

```python
from flask import session as flask_session

# Store the raw ID token for later use by the Connection_Mutator
if response and response.get("id_token"):
    flask_session["cognito_id_token"] = response["id_token"]
```

**Group resolution logic:**
1. Check `cognito:groups` in the userinfo response.
2. If absent, decode the raw `id_token` (no signature verification) to extract `cognito:groups`.
3. Iterate groups; first match in `COGNITO_GROUP_ROLE_MAP` wins.
4. Fall back to `_DEFAULT_ROLE = "Gamma"` if no match.

**Configuration constants (module-level):**
```python
COGNITO_GROUP_ROLE_MAP: dict[str, str] = {"superset_admins": "Admin"}
_DEFAULT_ROLE: str = "Gamma"
```

### 2. athena_db_connection_mutator (`athena_connection_mutator.py`)

A plain function matching the `DB_CONNECTION_MUTATOR` signature expected by `superset/models/core.py`:

```python
def athena_db_connection_mutator(
    uri: Any,
    connect_args: dict[str, Any],
    effective_username: str | None,
    security_manager: Any,
    source: str | None,
) -> tuple[Any, dict[str, Any]]:
```

**Internal helpers:**

```python
def _get_current_user_email() -> str | None:
    """Reads flask_login.current_user; returns None if anonymous or no request context."""

def _get_cognito_id_token() -> str | None:
    """Reads the Cognito ID token from the Flask session; returns None if absent."""

def _exchange_token_with_idc(id_token: str) -> str:
    """
    Calls sso-oidc:CreateTokenWithIAM to exchange the Cognito ID token for an
    Identity Center token. Returns the Identity Center token string.
    """

def _assume_role_with_idc_context(
    user_email: str, idc_token: str
) -> dict[str, str]:
    """
    Calls sts:AssumeRole with ProvidedContexts carrying the Identity Center token.
    Returns {aws_access_key_id, aws_secret_access_key, aws_session_token}.
    """
```

**Module-level configuration (from environment):**
```python
_ATHENA_DIALECT = re.compile(r"awsathena", re.IGNORECASE)
_EXECUTION_ROLE_ARN: str   # from ATHENA_EXECUTION_ROLE_ARN
_IDC_APPLICATION_ARN: str  # from IDC_APPLICATION_ARN (Identity Center application ARN)
_S3_STAGING_DIR: str       # from ATHENA_S3_STAGING_DIR
_AWS_REGION: str           # from AWS_REGION, default "eu-central-1"
```

**Token exchange call (`sso-oidc:CreateTokenWithIAM`):**
```python
sso_oidc = boto3.client("sso-oidc", region_name=_AWS_REGION)
response = sso_oidc.create_token_with_iam(
    clientId=_IDC_APPLICATION_ARN,
    grantType="urn:ietf:params:oauth:grant-type:jwt-bearer",
    assertion=cognito_id_token,
)
idc_token = response["idToken"]
```

**STS call parameters (with ProvidedContexts):**
```python
sts.assume_role(
    RoleArn=_EXECUTION_ROLE_ARN,
    RoleSessionName=<sanitized_email_max_64_chars>,
    ProvidedContexts=[
        {
            "ProviderArn": "arn:aws:iam::aws:contextProvider/IdentityCenter",
            "ContextAssertion": idc_token,
        }
    ],
    DurationSeconds=3600,
)
```

**URI rewrite format:**
```
awsathena+rest://{key}:{secret}@athena.{region}.amazonaws.com:443/
  ?s3_staging_dir={staging}&aws_session_token={token}[&<preserved_params>]
```
All credential values and query parameters are `urllib.parse.quote_plus`-encoded.

### 3. superset_config_docker.py

Wires the components into Superset's configuration system:

| Config Key | Value |
|---|---|
| `CUSTOM_SECURITY_MANAGER` | `CognitoSecurityManager` |
| `AUTH_TYPE` | `AUTH_OAUTH` |
| `AUTH_USER_REGISTRATION` | `True` |
| `AUTH_USER_REGISTRATION_ROLE` | `os.getenv("COGNITO_DEFAULT_ROLE", "Gamma")` |
| `AUTH_ROLES_MAPPING` | `{"Admin": ["Admin"], "Gamma": ["Gamma"]}` |
| `AUTH_ROLES_SYNC_AT_LOGIN` | `True` |
| `DB_CONNECTION_MUTATOR` | `athena_db_connection_mutator` |
| `OAUTH_PROVIDERS` | Cognito OIDC provider config |

The Cognito OIDC provider config uses `server_metadata_url` pointing to the Cognito User Pool's `.well-known/openid-configuration` endpoint, enabling automatic discovery of authorization, token, and JWKS endpoints.

### 4. Docker Infrastructure

**docker-compose.yml** additions (applied to `superset`, `superset-init`, `superset-worker` services):

- Volume: `${HOME}/.aws:/root/.aws:ro` — mounts host AWS credentials read-only
- Environment variables: `COGNITO_CLIENT_ID`, `COGNITO_CLIENT_SECRET`, `SUPERSET_PUBLIC_URL`

**requirements-local.txt:**
```
PyAthena[SQLAlchemy]>=3.0.0
```
Installed at container startup via `docker-bootstrap.sh` using `uv pip install`.

---

## Data Models

This feature introduces no new database models or schema migrations. All state is transient:

### STS Credential Payload (in-memory, per-request)

```python
{
    "aws_access_key_id": str,      # STS AccessKeyId
    "aws_secret_access_key": str,  # STS SecretAccessKey
    "aws_session_token": str,      # STS SessionToken
}
```
Credentials are valid for 3600 seconds (1 hour) and are embedded directly into the rewritten Athena SQLAlchemy URI. They are never persisted.

### Identity Center Token Exchange (in-memory, per-request)

The token exchange flow produces two intermediate values:

```python
# Step 1: sso-oidc:CreateTokenWithIAM response
{
    "idToken": str,          # Identity Center token — passed to STS ProvidedContexts
    "tokenType": str,        # e.g. "Bearer"
    "expiresIn": int,        # seconds until expiry
}

# Step 2: sts:AssumeRole ProvidedContexts parameter
[
    {
        "ProviderArn": "arn:aws:iam::aws:contextProvider/IdentityCenter",
        "ContextAssertion": str,  # the idToken from step 1
    }
]
```
Neither value is persisted; both are used only within the scope of a single `athena_db_connection_mutator` call.

### Flask Session Storage

The `CognitoSecurityManager` stores the Cognito ID token in the Flask session at login time:

```python
flask_session["cognito_id_token"] = str  # raw Cognito ID token JWT
```

This is a server-side session value (stored in the Superset session backend, not the browser cookie). It is read by the Connection_Mutator at query time and is cleared when the user logs out.

### Cognito User Info (returned from oauth_user_info)

```python
{
    "username": str,    # user's email — used as Superset username
    "email": str,
    "first_name": str,
    "last_name": str,
    "id": str,          # Cognito sub claim
    "name": str,        # display name
    "role_keys": list[str],  # single-element list: resolved Superset role
}
```
Flask-AppBuilder persists this to the Superset user table on first login; subsequent logins update the role if `AUTH_ROLES_SYNC_AT_LOGIN = True`.

### Session Name Sanitization

The STS `RoleSessionName` is derived from the user's email:
1. Apply `re.sub(r"[^\w+=,.@-]", "-", email)` — replace disallowed characters with `-`
2. Truncate to 64 characters

Allowed characters per AWS docs: `[a-zA-Z0-9+=,.@-]`. The regex `\w` covers `[a-zA-Z0-9_]`; combined with the explicit `+=,.@-` characters in the character class, this correctly allows all permitted characters.

### Environment Variable Contract

| Variable | Required | Default | Description |
|---|---|---|---|
| `ATHENA_EXECUTION_ROLE_ARN` | Yes | — | IAM role ARN to assume for Athena queries |
| `IDC_APPLICATION_ARN` | Yes | — | Identity Center application ARN for `CreateTokenWithIAM` |
| `ATHENA_S3_STAGING_DIR` | Yes | — | S3 URI for Athena query result staging |
| `AWS_REGION` | No | `eu-central-1` | AWS region for STS, SSO-OIDC, and Athena endpoints |
| `COGNITO_CLIENT_ID` | Yes | — | Cognito app client ID |
| `COGNITO_CLIENT_SECRET` | Yes | — | Cognito app client secret |
| `SUPERSET_PUBLIC_URL` | No | `http://localhost` | Public URL for OAuth callback |
| `COGNITO_DEFAULT_ROLE` | No | `Gamma` | Default Superset role for new users |

### Identity Center Prerequisites

The following Identity Center configuration is required outside of this codebase:

1. **Trusted Token Issuer**: An Identity Center Trusted Token Issuer must be configured to trust the Cognito User Pool's OIDC issuer URL. This maps Cognito users to Identity Center users by email.
2. **Identity Center Application**: A customer-managed Identity Center application must be created with the Trusted Token Issuer attached. The application ARN is the `IDC_APPLICATION_ARN` value.
3. **IAM Role Trust Policy**: The `ATHENA_EXECUTION_ROLE_ARN` role's trust policy must allow `sts:AssumeRole` with `sts:SetContext` from the Superset process principal, and must include the `sts:ProvidedContexts` condition key.

---

## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system — essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*

### Property 1: Session name sanitization strips disallowed characters

*For any* string used as a user email, the sanitized `RoleSessionName` must contain only characters from the set `[a-zA-Z0-9+=,.@-]` and must be at most 64 characters long.

**Validates: Requirements 4.2, 4.3**

---

### Property 2: Session name sanitization is idempotent

*For any* email that already contains only allowed STS session name characters and is at most 64 characters, applying the sanitization function twice produces the same result as applying it once.

**Validates: Requirements 4.2, 4.3**

---

### Property 3: Non-Athena URIs pass through unchanged

*For any* SQLAlchemy URI that does not contain the substring `awsathena` (case-insensitive), the mutator must return the original URI and `connect_args` objects unmodified.

**Validates: Requirements 5.3**

---

### Property 4: Unauthenticated connections pass through unchanged

*For any* Athena URI, when no authenticated user is present in the Flask session (anonymous or missing), the mutator must return the original URI and `connect_args` unmodified.

**Validates: Requirements 5.1, 5.2**

---

### Property 5: Rewritten URI preserves non-credential query parameters

*For any* Athena URI that contains non-credential query parameters (e.g., `schema`, `catalog`), the rewritten URI must contain all those parameters and must not contain the original credential parameters (`aws_access_key_id`, `aws_secret_access_key`, `aws_session_token` from the original URI).

**Validates: Requirements 3.7**

---

### Property 6: Rewritten URI contains all required credential components URL-encoded

*For any* successful STS credential response, the rewritten Athena URI must contain `aws_access_key_id`, `aws_secret_access_key`, `aws_session_token`, and `s3_staging_dir` as URL-encoded query parameters.

**Validates: Requirements 3.5, 3.6**

---

### Property 7: Group-to-role mapping is deterministic

*For any* list of Cognito groups, the resolved Superset role must be the value from `COGNITO_GROUP_ROLE_MAP` for the first matching group, or `"Gamma"` if no group matches.

**Validates: Requirements 2.3, 2.4**

---

### Property 8: TIP token exchange flow is invoked for authenticated Athena connections

*For any* authenticated Athena connection where a Cognito ID token is present in the Flask session, the mutator must call `sso-oidc:CreateTokenWithIAM` with the ID token as the `assertion`, and then call `sts:AssumeRole` with the resulting Identity Center token in the `ProvidedContexts` parameter — not with session tags.

**Validates: Requirements 3.3, 3.4, 8.3**

---

### Property 9: OIDC claim extraction works for all valid token shapes

*For any* valid Cognito userinfo response dict containing `email`, `sub`, and optional `given_name`/`family_name`/`name` fields, the `oauth_user_info` method must return a dict with non-empty `username`, `email`, and `id` fields derived from those claims.

**Validates: Requirements 1.3**

## Error Handling

### Missing ATHENA_EXECUTION_ROLE_ARN

- **Trigger**: `_EXECUTION_ROLE_ARN` is empty at call time.
- **Behavior**: `_assume_role_with_idc_context` raises `ValueError("ATHENA_EXECUTION_ROLE_ARN is not set — add it to docker/.env-local.")`.
- **Propagation**: Bubbles up through `athena_db_connection_mutator` to Superset's query engine, which surfaces it as a query error to the user.

### Missing IDC_APPLICATION_ARN

- **Trigger**: `_IDC_APPLICATION_ARN` is empty at call time.
- **Behavior**: `_exchange_token_with_idc` raises `ValueError("IDC_APPLICATION_ARN is not set — add it to docker/.env-local.")`.
- **Propagation**: Same as above — surfaces as a query error.

### Identity Center token exchange failure (CreateTokenWithIAM)

- **Trigger**: `boto3` raises `BotoCoreError` or `ClientError` (e.g., Trusted Token Issuer misconfigured, Cognito ID token expired, Identity Center application not found).
- **Behavior**:
  1. `logger.exception(...)` logs the full traceback at `ERROR` level.
  2. A `RuntimeError` is raised with a message including the user's email and a reference to the Identity Center Trusted Token Issuer configuration.
- **Propagation**: Superset surfaces this as a query error; the user sees a message directing them to their administrator.

### STS AssumeRole failure

- **Trigger**: `boto3` raises `BotoCoreError` or `ClientError` (e.g., insufficient permissions, invalid role ARN, ProvidedContexts rejected).
- **Behavior**:
  1. `logger.exception(...)` logs the full traceback at `ERROR` level.
  2. A `RuntimeError` is raised with a message including the user's email and a reference to the IAM trust policy.
- **Propagation**: Superset surfaces this as a query error; the user sees a message directing them to their administrator.

### Missing Cognito ID token in session

- **Trigger**: The Flask session does not contain `cognito_id_token` (e.g., session expired, user logged in before the feature was enabled).
- **Behavior**: `_get_cognito_id_token` returns `None`; the mutator logs a warning and returns the original URI unchanged, allowing ambient AWS credentials to be used.

### Missing or invalid OIDC claims

- **Trigger**: ID token cannot be decoded, or required claims (`email`, `sub`) are absent.
- **Behavior**: `oauth_user_info` logs a warning and returns a partial dict; Flask-AppBuilder's login flow will deny the login if required fields are missing.
- **Cognito groups decode failure**: Caught with a broad `except Exception` (intentional — any JWT decode error should not block login); logs a warning and falls back to the default role.

### No authenticated user (fallback)

- **Trigger**: `current_user` is anonymous or `flask_login` raises `RuntimeError` (no request context).
- **Behavior**: `_get_current_user_email` returns `None`; the mutator logs a warning and returns the original URI unchanged, allowing ambient AWS credentials to be used.

---

## Testing Strategy

### Dual Testing Approach

Both unit tests and property-based tests are required. Unit tests cover specific examples, integration points, and error conditions. Property-based tests verify universal correctness across all inputs.

### Unit Tests

Location: `tests/unit_tests/docker/pythonpath_dev/`

Key test cases:

**`test_athena_connection_mutator.py`**
- Non-Athena URI is returned unchanged (example: `postgresql://...`)
- Anonymous user returns original URI unchanged
- Missing `ATHENA_EXECUTION_ROLE_ARN` raises `ValueError`
- Missing `IDC_APPLICATION_ARN` raises `ValueError`
- `CreateTokenWithIAM` `BotoCoreError` raises `RuntimeError` with email in message
- STS `AssumeRole` `ClientError` raises `RuntimeError` with email in message
- Missing Cognito ID token in session falls back to ambient credentials
- Successful TIP flow rewrites URI with credentials (mock SSO-OIDC + STS)
- `CreateTokenWithIAM` is called with correct `grantType` and `assertion`
- `AssumeRole` is called with `ProvidedContexts` (not `Tags`)
- Non-credential query params (e.g., `?schema=mydb`) are preserved in rewritten URI
- Credential params in original URI are stripped from rewritten URI
- All credential values in rewritten URI are URL-encoded

**`test_custom_sso_security_manager.py`**
- Groups from userinfo response are mapped correctly
- Groups from ID token fallback are mapped correctly
- First matching group wins when multiple groups match
- No matching group falls back to `"Gamma"`
- JWT decode failure logs warning and falls back to default role
- `email` and `sub` are correctly extracted from OIDC claims
- ID token is stored in Flask session after successful login

### Property-Based Tests

Location: `tests/unit_tests/docker/pythonpath_dev/test_properties.py`

Library: **Hypothesis** (already available in the Superset test environment via `pytest`).

Each property test must run a minimum of 100 iterations (Hypothesis default is 100; use `@settings(max_examples=100)`).

**Tag format for each test:**
```python
# Feature: athena-identity-propagation, Property N: <property_text>
```

**Property 1 test** — Session name sanitization:
```python
# Feature: athena-identity-propagation, Property 1: sanitized session name contains only allowed chars and is ≤64 chars
@given(st.text())
@settings(max_examples=100)
def test_session_name_sanitization(email):
    result = re.sub(r"[^\w+=,.@-]", "-", email)[:64]
    assert len(result) <= 64
    assert re.fullmatch(r"[a-zA-Z0-9+=,.@_\-]*", result)
```

**Property 2 test** — Sanitization idempotence:
```python
# Feature: athena-identity-propagation, Property 2: sanitization is idempotent for already-safe names
@given(st.text(alphabet=st.characters(whitelist_categories=("Lu", "Ll", "Nd")), max_size=64))
@settings(max_examples=100)
def test_session_name_idempotent(safe_email):
    once = re.sub(r"[^\w+=,.@-]", "-", safe_email)[:64]
    twice = re.sub(r"[^\w+=,.@-]", "-", once)[:64]
    assert once == twice
```

**Property 3 test** — Non-Athena URI passthrough:
```python
# Feature: athena-identity-propagation, Property 3: non-Athena URIs pass through unchanged
@given(st.text().filter(lambda s: "awsathena" not in s.lower()))
@settings(max_examples=100)
def test_non_athena_uri_passthrough(uri):
    result_uri, result_args = athena_db_connection_mutator(uri, {}, None, None, None)
    assert result_uri == uri
    assert result_args == {}
```

**Property 4 test** — Unauthenticated passthrough:
```python
# Feature: athena-identity-propagation, Property 4: unauthenticated connections pass through unchanged
@given(st.text(min_size=1).map(lambda s: "awsathena+rest://" + s))
@settings(max_examples=100)
def test_unauthenticated_passthrough(athena_uri):
    # With anonymous current_user mocked
    result_uri, result_args = athena_db_connection_mutator(athena_uri, {}, None, None, None)
    assert result_uri == athena_uri
```

**Property 5 test** — Non-credential params preserved:
```python
# Feature: athena-identity-propagation, Property 5: non-credential query params are preserved in rewritten URI
@given(
    st.fixed_dictionaries({
        "schema": st.text(min_size=1, alphabet=st.characters(whitelist_categories=("Lu", "Ll"))),
        "catalog": st.text(min_size=1, alphabet=st.characters(whitelist_categories=("Lu", "Ll"))),
    })
)
@settings(max_examples=100)
def test_non_credential_params_preserved(extra_params):
    # Build URI with extra params, mock SSO-OIDC + STS, verify params survive rewrite
    ...
```

**Property 6 test** — Rewritten URI contains all credential components:
```python
# Feature: athena-identity-propagation, Property 6: rewritten URI contains all required credential components URL-encoded
@given(
    st.fixed_dictionaries({
        "AccessKeyId": st.text(min_size=1),
        "SecretAccessKey": st.text(min_size=1),
        "SessionToken": st.text(min_size=1),
    })
)
@settings(max_examples=100)
def test_rewritten_uri_has_credentials(creds):
    # Mock SSO-OIDC + STS to return creds, verify rewritten URI contains all three encoded
    ...
```

**Property 7 test** — Group-to-role mapping determinism:
```python
# Feature: athena-identity-propagation, Property 7: group-to-role mapping is deterministic
@given(st.lists(st.text()))
@settings(max_examples=100)
def test_group_role_mapping_deterministic(groups):
    role = _DEFAULT_ROLE
    for group in groups:
        if group in COGNITO_GROUP_ROLE_MAP:
            role = COGNITO_GROUP_ROLE_MAP[group]
            break
    # Calling twice with same input must yield same result
    role2 = _DEFAULT_ROLE
    for group in groups:
        if group in COGNITO_GROUP_ROLE_MAP:
            role2 = COGNITO_GROUP_ROLE_MAP[group]
            break
    assert role == role2
```

**Property 8 test** — TIP token exchange flow:
```python
# Feature: athena-identity-propagation, Property 8: TIP token exchange flow is invoked for authenticated Athena connections
@given(
    st.text(min_size=1, alphabet=st.characters(whitelist_categories=("Lu", "Ll", "Nd"))).map(
        lambda s: s + "@example.com"
    )
)
@settings(max_examples=100)
def test_tip_token_exchange_flow(user_email):
    # Mock current_user with user_email, mock Flask session with cognito_id_token
    # Mock SSO-OIDC CreateTokenWithIAM and STS AssumeRole
    # Verify: CreateTokenWithIAM called with assertion=id_token
    # Verify: AssumeRole called with ProvidedContexts (not Tags/TransitiveTagKeys)
    ...
```

**Property 9 test** — OIDC claim extraction:
```python
# Feature: athena-identity-propagation, Property 9: OIDC claim extraction works for all valid token shapes
@given(
    st.fixed_dictionaries({
        "email": st.emails(),
        "sub": st.uuids().map(str),
        "given_name": st.text(min_size=0, max_size=50),
        "family_name": st.text(min_size=0, max_size=50),
    })
)
@settings(max_examples=100)
def test_oidc_claim_extraction(claims):
    # Mock the Cognito userinfo endpoint to return claims
    # Call oauth_user_info and verify username, email, id are non-empty and correct
    ...
```

### Running Tests

```bash
# Unit + property tests for this feature
pytest tests/unit_tests/docker/pythonpath_dev/ -v

# Property tests only
pytest tests/unit_tests/docker/pythonpath_dev/test_properties.py -v

# With Hypothesis database for reproducibility
pytest tests/unit_tests/docker/pythonpath_dev/ --hypothesis-seed=0
```
