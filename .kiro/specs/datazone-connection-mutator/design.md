# Design Document: DataZone Connection Mutator

## Overview

This feature implements a Superset `DB_CONNECTION_MUTATOR` hook that intercepts Athena connections using the `CredentialsProvider=DataZoneIdc` pattern and exchanges the current user's Cognito ID token for DataZone environment credentials through a multi-step token chain. The mutator enables per-user access to DataZone-governed Glue catalogs by propagating the user's identity through the full DataZone credential chain: Cognito → STS AssumeRoleWithWebIdentity → SSO-OIDC CreateTokenWithIAM → DataZone RedeemAccessToken → GetEnvironmentCredentials.

The mutator caches intermediate and final credentials in Redis with appropriate TTLs, handles token refresh, and supports both Flask web request context and Celery worker context (via Redis fallback). It follows the same architectural patterns as the existing `athena_rest_connection_mutator.py` (TIP flow) but implements the DataZone IDC credential chain instead.

## Architecture

```mermaid
graph TD
    subgraph Superset
        A[DB_CONNECTION_MUTATOR Hook] --> B{Is DataZoneIdc?}
        B -->|No| Z[Return URI unchanged]
        B -->|Yes| C[Resolve User Email]
        C --> D[Get Cognito ID Token]
        D --> E{Token in Cache?}
    end

    subgraph "Redis Cache Layer"
        R1[Cognito Tokens]
        R2[Intermediary Role Creds]
        R3[IDC Access Tokens]
        R4[Domain Execution Creds]
        R5[Environment Creds]
    end

    subgraph "AWS Token Exchange Chain"
        E -->|Miss/Expired| F[STS AssumeRoleWithWebIdentity]
        F --> G[SSO-OIDC CreateTokenWithIAM]
        G --> H[DataZone RedeemAccessToken]
        H --> I[DataZone GetEnvironmentCredentials]
    end

    E -->|Hit| J[Use Cached Creds]
    I --> J
    J --> K[Rewrite SQLAlchemy URI]

    D -.-> R1
    F -.-> R2
    G -.-> R3
    H -.-> R4
    I -.-> R5
```

## Sequence Diagrams

### Main Token Exchange Flow

```mermaid
sequenceDiagram
    participant S as Superset (Mutator)
    participant Redis as Redis Cache
    participant STS as AWS STS
    participant OIDC as SSO-OIDC
    participant DZ as DataZone API
    participant DZSvc as DataZone Service

    S->>S: Intercept Athena connection (DataZoneIdc)
    S->>S: Resolve user email (Flask/Celery context)
    S->>Redis: Check cached environment credentials
    
    alt Cache Hit (not expired)
        Redis-->>S: Return cached credentials
    else Cache Miss or Expired
        S->>S: Get Cognito ID token (session/Redis)
        S->>Redis: Check cached intermediary role creds
        
        alt Intermediary creds cached
            Redis-->>S: Return cached role creds
        else Need fresh intermediary creds
            S->>STS: AssumeRoleWithWebIdentity(OIDC_ROLE_ARN, cognito_token)
            STS-->>S: Temporary IAM credentials
            S->>Redis: Cache intermediary creds (TTL=850s)
        end

        S->>Redis: Check cached IDC access token
        alt IDC token cached
            Redis-->>S: Return cached IDC token
        else Need fresh IDC token
            S->>OIDC: CreateTokenWithIAM(IDC_APP_ARN, cognito_token)
            OIDC-->>S: IDC access token + expires_in
            S->>Redis: Cache IDC token (TTL=expires_in - 60s)
        end

        S->>Redis: Check cached domain execution creds
        alt Domain creds cached
            Redis-->>S: Return cached domain creds
        else Need fresh domain creds
            S->>DZ: POST /sso/redeem-token (domain_id, access_token)
            DZ-->>S: DomainExecutionRole credentials
            S->>Redis: Cache domain creds (TTL based on expiration)
        end

        S->>Redis: Check cached environment creds
        alt Environment creds cached
            Redis-->>S: Return cached env creds
        else Need fresh env creds
            S->>DZSvc: GetEnvironmentCredentials(domain_id, env_id)
            DZSvc-->>S: Final environment credentials
            S->>Redis: Cache env creds (TTL based on expiration)
        end
    end

    S->>S: Rewrite SQLAlchemy URI with credentials
```

### Cognito Token Retrieval (Web vs Worker Context)

```mermaid
sequenceDiagram
    participant M as Mutator
    participant FS as Flask Session
    participant Redis as Redis
    participant Cognito as Cognito IDP

    alt Web Request Context
        M->>FS: Get cognito_id_token from session
        FS-->>M: ID token (or None)
    else Celery Worker Context
        M->>Redis: Get cognito tokens by user email
        Redis-->>M: {id_token, refresh_token, ...}
    end

    alt Token expired
        M->>Cognito: InitiateAuth(REFRESH_TOKEN_AUTH)
        Cognito-->>M: New ID token
        M->>Redis: Update cached tokens
    end

```

## Components and Interfaces

### Component 1: DataZoneConnectionMutator (Hook Entry Point)

**Purpose**: Superset `DB_CONNECTION_MUTATOR` hook that intercepts Athena connections with `CredentialsProvider=DataZoneIdc` and rewrites the SQLAlchemy URI with per-user DataZone environment credentials.

```python
def datazone_connection_mutator(
    uri: SqlaURL,
    connect_args: dict[str, Any],
    effective_username: str | None,
    security_manager: Any,
    source: str | None,
) -> tuple[SqlaURL, dict[str, Any]]:
    """
    Superset DB_CONNECTION_MUTATOR hook for DataZone IDC credential flow.
    
    Detects DataZoneIdc connections by checking for CredentialsProvider=DataZoneIdc
    in the connection string query parameters. Non-matching connections are
    returned unchanged.
    """
    ...
```

**Responsibilities**:
- Detect DataZoneIdc connections via query parameter inspection
- Resolve the current user's email from Flask-Login or Celery context
- Orchestrate the credential chain (delegating to TokenChainManager)
- Rewrite the SQLAlchemy URI with the final environment credentials
- Handle fallback when no Cognito token is available

### Component 2: TokenChainManager

**Purpose**: Orchestrates the multi-step token exchange chain with caching at each level.

```python
class TokenChainManager:
    """Manages the DataZone IDC token exchange chain with Redis caching."""

    def __init__(self, redis_client: Redis, region: str):
        self._redis = redis_client
        self._region = region

    def get_environment_credentials(
        self,
        user_email: str,
        cognito_id_token: str,
        domain_id: str,
        environment_id: str,
        oidc_role_arn: str,
        idc_application_arn: str,
    ) -> dict[str, str]:
        """
        Execute the full token chain, using cached values where available.
        Returns final environment credentials (access_key, secret_key, session_token).
        """
        ...

    def _get_intermediary_credentials(
        self, user_email: str, cognito_id_token: str, oidc_role_arn: str
    ) -> dict[str, str]:
        """Step 1: AssumeRoleWithWebIdentity → intermediary IAM credentials."""
        ...

    def _get_idc_access_token(
        self, user_email: str, cognito_id_token: str, intermediary_creds: dict[str, str], idc_application_arn: str
    ) -> str:
        """Step 2: CreateTokenWithIAM → IDC access token."""
        ...

    def _redeem_access_token(
        self, user_email: str, idc_access_token: str, domain_id: str
    ) -> dict[str, str]:
        """Step 3: RedeemAccessToken → DomainExecutionRole credentials."""
        ...

    def _get_env_credentials(
        self, user_email: str, domain_creds: dict[str, str], domain_id: str, environment_id: str
    ) -> dict[str, str]:
        """Step 4: GetEnvironmentCredentials → final environment credentials."""
        ...
```

**Responsibilities**:
- Execute each step of the token chain
- Check Redis cache before making API calls
- Store results in Redis with appropriate TTLs
- Handle errors and provide meaningful error messages

### Component 3: RedisTokenCache

**Purpose**: Manages Redis-based caching of tokens and credentials at each level of the chain.

```python
class RedisTokenCache:
    """Redis cache for multi-level token chain credentials."""

    PREFIX = "dz_mutator:"

    def __init__(self, redis_client: Redis):
        self._redis = redis_client

    def get_cached(self, cache_key: str) -> dict[str, Any] | None:
        """Retrieve cached value if not expired."""
        ...

    def set_cached(self, cache_key: str, value: dict[str, Any], ttl_seconds: int) -> None:
        """Store value with TTL."""
        ...

    def build_key(self, user_email: str, step: str, *identifiers: str) -> str:
        """Build a cache key: dz_mutator:{step}:{user_email}:{identifiers}"""
        ...
```

**Responsibilities**:
- Build namespaced cache keys per user and per chain step
- Serialize/deserialize cached credentials as JSON
- Apply TTL with expiry buffer to avoid race conditions
- Provide cache invalidation when needed

### Component 4: ConnectionStringParser

**Purpose**: Extracts DataZone-specific parameters from the Athena connection string.

```python
@dataclass
class DataZoneConnectionParams:
    """Parameters extracted from a DataZoneIdc connection string."""
    domain_id: str
    environment_id: str
    domain_region: str
    identity_center_issuer_url: str
    workgroup: str
    region: str
    s3_staging_dir: str
    catalog_name: str

def parse_datazone_params(uri: SqlaURL) -> DataZoneConnectionParams | None:
    """
    Extract DataZone parameters from the connection string query params.
    Returns None if this is not a DataZoneIdc connection.
    """
    ...
```

**Responsibilities**:
- Detect `CredentialsProvider=DataZoneIdc` in query parameters
- Extract domain ID, environment ID, region, workgroup, etc.
- Fall back to environment variables for missing parameters
- Validate required parameters are present

## Data Models

### DataZoneConnectionParams

```python
@dataclass
class DataZoneConnectionParams:
    """Parameters extracted from a DataZoneIdc connection string."""
    domain_id: str                      # e.g., "dzd-djkh2xy1il745n"
    environment_id: str                 # e.g., "543huadved7z0r"
    domain_region: str                  # e.g., "eu-central-1"
    identity_center_issuer_url: str     # e.g., "https://identitycenter.amazonaws.com/ssoins-..."
    workgroup: str                      # e.g., "workgroup-568od5rs4kpsaz-543huadved7z0r"
    region: str                         # e.g., "eu-central-1"
    s3_staging_dir: str                 # S3 path for Athena query results
    catalog_name: str                   # Glue catalog name
```

**Validation Rules**:
- `domain_id` must start with "dzd-"
- `environment_id` must be non-empty
- `domain_region` must be a valid AWS region format
- `workgroup` must be non-empty

### CachedCredentials

```python
@dataclass
class CachedCredentials:
    """Wrapper for cached AWS credentials with expiry tracking."""
    access_key_id: str
    secret_access_key: str
    session_token: str
    expiration: float           # Unix timestamp
    cached_at: float            # When this was cached
    source_token_hash: str      # Hash of the source token (for invalidation)
```

**Validation Rules**:
- `expiration` must be in the future at cache time
- `source_token_hash` used to detect when upstream token has changed (invalidate downstream cache)

### Redis Cache Key Schema

| Step | Key Pattern | TTL | Value |
|------|-------------|-----|-------|
| Intermediary Role | `dz_mutator:intermediary:{user}:{role_arn_hash}` | 850s (15min role - 50s buffer) | JSON credentials |
| IDC Access Token | `dz_mutator:idc_token:{user}:{app_arn_hash}` | `expires_in - 60s` | JSON {access_token, expires_in} |
| Domain Execution | `dz_mutator:domain_creds:{user}:{domain_id}` | Based on expiration field - 60s | JSON credentials |
| Environment Creds | `dz_mutator:env_creds:{user}:{domain_id}:{env_id}` | Based on expiration field - 60s | JSON credentials |


## Key Functions with Formal Specifications

### Function 1: datazone_connection_mutator()

```python
def datazone_connection_mutator(
    uri: SqlaURL,
    connect_args: dict[str, Any],
    effective_username: str | None,
    security_manager: Any,
    source: str | None,
) -> tuple[SqlaURL, dict[str, Any]]:
```

**Preconditions:**
- `uri` is a valid SQLAlchemy URL object
- `connect_args` is a valid dictionary (may be empty)

**Postconditions:**
- If URI dialect is not `awsathena`, returns `(uri, connect_args)` unchanged
- If URI does not contain `CredentialsProvider=DataZoneIdc`, returns unchanged
- If no authenticated user is found, returns unchanged (logs warning)
- If no Cognito token is available, returns unchanged (logs warning)
- On success: returns a new URI with `username=access_key_id`, `password=secret_access_key`, `aws_session_token` in query params
- Original URI is never mutated; a new URL object is always created
- `connect_args` is returned unchanged

**Loop Invariants:** N/A

### Function 2: TokenChainManager.get_environment_credentials()

```python
def get_environment_credentials(
    self,
    user_email: str,
    cognito_id_token: str,
    domain_id: str,
    environment_id: str,
    oidc_role_arn: str,
    idc_application_arn: str,
) -> dict[str, str]:
```

**Preconditions:**
- `user_email` is a non-empty string
- `cognito_id_token` is a valid, non-expired JWT (or refreshable)
- `domain_id` starts with "dzd-"
- `environment_id` is non-empty
- `oidc_role_arn` is a valid IAM role ARN trusted by the Cognito identity provider
- `idc_application_arn` is a valid Identity Center application ARN

**Postconditions:**
- Returns dict with keys: `aws_access_key_id`, `aws_secret_access_key`, `aws_session_token`
- All returned credential values are non-empty strings
- Credentials are valid (not expired) at time of return
- If any step fails, raises `RuntimeError` with descriptive message
- Intermediate results are cached in Redis for subsequent calls

**Loop Invariants:** N/A

### Function 3: _redeem_access_token()

```python
def _redeem_access_token(
    self, user_email: str, idc_access_token: str, domain_id: str
) -> dict[str, str]:
```

**Preconditions:**
- `idc_access_token` is a valid IDC access token (from CreateTokenWithIAM)
- `domain_id` is a valid DataZone domain identifier
- Network access to `https://datazone.{region}.api.aws` is available

**Postconditions:**
- Returns dict with keys: `access_key_id`, `secret_access_key`, `session_token`, `expiration`
- The returned credentials belong to the DomainExecutionRole
- On HTTP error (non-2xx), raises `RuntimeError` with status code and response body
- On network error, raises `RuntimeError` with connection details

**Loop Invariants:** N/A

### Function 4: parse_datazone_params()

```python
def parse_datazone_params(uri: SqlaURL) -> DataZoneConnectionParams | None:
```

**Preconditions:**
- `uri` is a valid SQLAlchemy URL object with accessible `query` attribute

**Postconditions:**
- Returns `None` if `CredentialsProvider` query param is not `DataZoneIdc` (case-insensitive)
- Returns `DataZoneConnectionParams` with all fields populated from query params or env var fallbacks
- Raises `ValueError` if required params (`domain_id`, `environment_id`) are missing from both URI and env vars

**Loop Invariants:** N/A

## Algorithmic Pseudocode

### Main Credential Chain Algorithm

```python
def get_environment_credentials(user_email, cognito_id_token, domain_id, environment_id, oidc_role_arn, idc_app_arn):
    """
    Execute the full DataZone IDC credential chain with caching at each level.
    
    The chain is: Cognito → AssumeRoleWithWebIdentity → CreateTokenWithIAM 
                  → RedeemAccessToken → GetEnvironmentCredentials
    
    Each step checks Redis cache first. If cached value exists and is not expired,
    it is used directly. Otherwise, the API call is made and the result is cached.
    
    Cache invalidation: If the source Cognito token changes (detected via hash),
    all downstream cached values for that user are invalidated.
    """
    # Check if final environment credentials are already cached
    env_cache_key = f"dz_mutator:env_creds:{user_email}:{domain_id}:{environment_id}"
    cached_env = redis.get(env_cache_key)
    if cached_env and cached_env.source_token_hash == hash(cognito_id_token):
        if not is_expired(cached_env, buffer=60):
            return cached_env.credentials

    # Step 1: Get intermediary IAM credentials via AssumeRoleWithWebIdentity
    intermediary_key = f"dz_mutator:intermediary:{user_email}:{hash(oidc_role_arn)}"
    intermediary_creds = redis.get(intermediary_key)
    if not intermediary_creds or is_expired(intermediary_creds, buffer=60):
        intermediary_creds = sts.assume_role_with_web_identity(
            RoleArn=oidc_role_arn,
            RoleSessionName=f"dz-{sanitize(user_email)}",
            WebIdentityToken=cognito_id_token,
            DurationSeconds=900,
        )
        redis.setex(intermediary_key, ttl=850, value=intermediary_creds)

    # Step 2: Get IDC access token via CreateTokenWithIAM
    idc_key = f"dz_mutator:idc_token:{user_email}:{hash(idc_app_arn)}"
    idc_token_data = redis.get(idc_key)
    if not idc_token_data or is_expired(idc_token_data, buffer=60):
        session = boto3.Session(credentials=intermediary_creds)
        sso_oidc = session.client("sso-oidc")
        token_response = sso_oidc.create_token_with_iam(
            clientId=idc_app_arn,
            grantType="urn:ietf:params:oauth:grant-type:jwt-bearer",
            assertion=cognito_id_token,
        )
        idc_access_token = token_response["accessToken"]
        ttl = token_response["expiresIn"] - 60
        redis.setex(idc_key, ttl=ttl, value=idc_access_token)
    else:
        idc_access_token = idc_token_data

    # Step 3: Redeem access token for DomainExecutionRole credentials
    domain_key = f"dz_mutator:domain_creds:{user_email}:{domain_id}"
    domain_creds = redis.get(domain_key)
    if not domain_creds or is_expired(domain_creds, buffer=60):
        response = http_post(
            url=f"https://datazone.{region}.api.aws/sso/redeem-token",
            json={"domainId": domain_id, "accessToken": idc_access_token},
        )
        domain_creds = response["credentials"]
        ttl = int(domain_creds["expiration"] - time.time() - 60)
        redis.setex(domain_key, ttl=ttl, value=domain_creds)

    # Step 4: Get final environment credentials
    session = boto3.Session(credentials=domain_creds)
    dz_client = session.client("datazone")
    response = dz_client.get_environment_credentials(
        domainIdentifier=domain_id,
        environmentIdentifier=environment_id,
    )
    env_creds = {
        "aws_access_key_id": response["accessKeyId"],
        "aws_secret_access_key": response["secretAccessKey"],
        "aws_session_token": response["sessionToken"],
    }
    ttl = int(response["expiration"] - time.time() - 60)
    redis.setex(env_cache_key, ttl=ttl, value=env_creds)

    return env_creds
```

**Preconditions:**
- cognito_id_token is a valid, non-expired Cognito ID token JWT
- oidc_role_arn trusts the Cognito identity provider for AssumeRoleWithWebIdentity
- idc_app_arn is configured to accept JWT bearer grants from the Cognito provider
- The user (identified by cognito token sub) is a member of the DataZone project
- Redis is available and writable

**Postconditions:**
- Returns valid, non-expired AWS credentials for the target environment
- All intermediate tokens/credentials are cached in Redis
- On any step failure, raises RuntimeError with step identification and error details

**Loop Invariants:** N/A (sequential chain, no loops)

### Connection String Detection Algorithm

```python
def detect_and_mutate(uri, connect_args, effective_username, security_manager, source):
    """
    Entry point: detect DataZoneIdc connections and apply credential injection.
    """
    # Guard: only process Athena connections
    if not re.match(r"awsathena", uri.drivername, re.IGNORECASE):
        return uri, connect_args

    # Guard: only process DataZoneIdc credential provider
    query_params = dict(uri.query)
    credentials_provider = query_params.get("CredentialsProvider", "")
    if credentials_provider.lower() != "datazoneidc":
        return uri, connect_args

    # Parse DataZone-specific parameters
    dz_params = parse_datazone_params(uri)
    if dz_params is None:
        log.warning("DataZoneIdc connection missing required parameters")
        return uri, connect_args

    # Resolve current user
    user_email = get_current_user_email()
    if not user_email:
        log.warning("No authenticated user — cannot obtain DataZone credentials")
        return uri, connect_args

    # Get Cognito ID token (session or Redis)
    cognito_token = get_cognito_id_token(user_email)
    if not cognito_token:
        log.warning("No Cognito token for %s — cannot proceed with DataZone flow", user_email)
        return uri, connect_args

    # Execute token chain
    creds = token_chain_manager.get_environment_credentials(
        user_email=user_email,
        cognito_id_token=cognito_token,
        domain_id=dz_params.domain_id,
        environment_id=dz_params.environment_id,
        oidc_role_arn=OIDC_ROLE_ARN,
        idc_application_arn=IDC_APPLICATION_ARN,
    )

    # Build new URI with credentials
    return build_new_url(uri, creds, dz_params), connect_args
```

**Preconditions:**
- uri is a valid SQLAlchemy URL
- Environment variables OIDC_ROLE_ARN and IDC_APPLICATION_ARN are set

**Postconditions:**
- Non-Athena URIs returned unchanged
- Non-DataZoneIdc URIs returned unchanged
- On success: new URI with injected credentials, original query params preserved (minus credential-related ones)
- On failure at any guard: original URI returned unchanged with warning logged

## Example Usage

```python
# --- superset_config.py ---
from datazone_connection_mutator import datazone_connection_mutator

# Register as Superset's connection mutator
DB_CONNECTION_MUTATOR = datazone_connection_mutator


# --- Connection String (configured in Superset UI) ---
# awsathena+rest://athena.eu-central-1.amazonaws.com:443/?
#   CredentialsProvider=DataZoneIdc&
#   DataZoneDomainId=dzd-djkh2xy1il745n&
#   DataZoneEnvironmentId=543huadved7z0r&
#   DataZoneDomainRegion=eu-central-1&
#   IdentityCenterIssuerUrl=https://identitycenter.amazonaws.com/ssoins-69877cf557cb578c&
#   work_group=workgroup-568od5rs4kpsaz-543huadved7z0r&
#   region_name=eu-central-1&
#   catalog_name=AwsDataCatalog


# --- What happens at query time ---
# 1. User clicks "Run Query" in SQL Lab
# 2. Superset calls DB_CONNECTION_MUTATOR with the raw URI
# 3. Mutator detects CredentialsProvider=DataZoneIdc
# 4. Mutator resolves user email from Flask session
# 5. Mutator executes token chain (with Redis caching)
# 6. Mutator rewrites URI:
#    awsathena+rest://AKIAXXXXXXXX:SecretKey@athena.eu-central-1.amazonaws.com:443/?
#      aws_session_token=FwoGZX...&
#      work_group=workgroup-568od5rs4kpsaz-543huadved7z0r&
#      region_name=eu-central-1&
#      catalog_name=AwsDataCatalog
# 7. PyAthena connects with the injected credentials


# --- Environment Variables (docker/.env-local) ---
# OIDC_ROLE_ARN=arn:aws:iam::666839000341:role/AndriSupersetPoc
# IDC_APPLICATION_ARN=arn:aws:sso::666839000341:application/ssoins-69877cf557cb578c/apl-6987d4bb15a48958
# DATAZONE_DOMAIN_ID=dzd-djkh2xy1il745n
# DATAZONE_ENVIRONMENT_ID=543huadved7z0r
# AWS_REGION=eu-central-1
# REDIS_HOST=redis
# REDIS_PORT=6379
```

## Correctness Properties

The following properties must hold for the implementation to be correct:

1. **Idempotency**: Calling the mutator multiple times with the same URI and user context produces the same rewritten URI (modulo credential rotation).

2. **Non-interference**: Non-DataZoneIdc connections are never modified. The mutator returns them exactly as received.

3. **Cache consistency**: If a cached credential is returned, it must not be expired (accounting for the 60-second buffer). Expired cache entries must trigger a fresh API call.

4. **Token chain ordering**: Each step in the chain depends on the output of the previous step. Steps cannot be reordered or skipped.

5. **User isolation**: Credentials cached for user A are never returned for user B. Cache keys include the user email.

6. **Graceful degradation**: If any step in the chain fails, the mutator logs a warning and returns the original URI unchanged (no partial credential injection).

7. **Source token invalidation**: If the Cognito ID token changes (e.g., after refresh), downstream cached values keyed to the old token are not used.

8. **Thread safety**: Module-level state (Redis client, environment variables) is read-only after initialization. Per-request state flows through function parameters.

9. **Context independence**: The mutator works identically in Flask web context and Celery worker context, differing only in how the Cognito token is retrieved (session vs Redis).

10. **Credential scrubbing**: The rewritten URI logged for debugging never contains the full secret access key or session token.

## Error Handling

### Error Scenario 1: Expired Cognito Token (No Refresh Token Available)

**Condition**: The Cognito ID token in the session/Redis is expired and no refresh token is stored.
**Response**: Log warning with user email. Return original URI unchanged.
**Recovery**: User must re-authenticate via the Cognito OAuth flow (redirect to login).

### Error Scenario 2: AssumeRoleWithWebIdentity Fails

**Condition**: STS rejects the web identity token (e.g., role trust policy mismatch, token audience mismatch).
**Response**: Raise `RuntimeError` with the STS error code and message. Log the role ARN and token issuer for debugging.
**Recovery**: Verify OIDC_ROLE_ARN trust policy includes the Cognito user pool as a trusted identity provider with correct audience condition.

### Error Scenario 3: CreateTokenWithIAM Fails (InvalidGrantException)

**Condition**: The IDC application rejects the Cognito token (audience mismatch, token expired, Trusted Token Issuer misconfigured).
**Response**: Raise `RuntimeError` with error code. Log the IDC application ARN and Cognito token claims (iss, aud, exp).
**Recovery**: Verify the Identity Center Trusted Token Issuer configuration matches the Cognito user pool issuer and audience.

### Error Scenario 4: RedeemAccessToken HTTP Error

**Condition**: The DataZone REST API returns a non-2xx response (e.g., 403 Forbidden, 400 Bad Request).
**Response**: Raise `RuntimeError` with HTTP status code and response body. Log the domain ID and (redacted) token prefix.
**Recovery**: Verify the domain ID is correct and the user's IDC identity has access to the domain.

### Error Scenario 5: GetEnvironmentCredentials AccessDeniedException

**Condition**: The user is not a member of the DataZone project that owns the environment.
**Response**: Raise `RuntimeError` with the AccessDeniedException message. Log domain ID and environment ID.
**Recovery**: Add the user's Identity Center identity as a member of the DataZone project.

### Error Scenario 6: Redis Unavailable

**Condition**: Redis connection fails (network issue, Redis down).
**Response**: Log warning. Proceed without caching — execute the full token chain on every request.
**Recovery**: Automatic once Redis is restored. No data loss (cache is ephemeral).

## Testing Strategy

### Unit Testing Approach

- Mock all AWS API calls (boto3 clients) using `unittest.mock.patch` or `moto`
- Mock Redis using `fakeredis` library
- Test each step of the token chain independently
- Test cache hit/miss scenarios
- Test connection string parsing with various URI formats
- Test error handling for each failure mode
- Test user context resolution (Flask session vs Celery/Redis)

**Key test cases:**
1. Happy path: full chain execution with all cache misses
2. Full cache hit: all steps return cached values
3. Partial cache hit: some steps cached, others need fresh calls
4. Token expiry: cached value expired, triggers refresh
5. Source token change: Cognito token rotated, invalidates downstream cache
6. Non-DataZoneIdc connection: returned unchanged
7. Missing environment variables: appropriate error raised
8. Redis failure: graceful degradation (no caching, still works)

### Property-Based Testing Approach

**Property Test Library**: `hypothesis`

Properties to test:
- For any valid connection string with `CredentialsProvider=DataZoneIdc`, the parser extracts all required fields
- For any non-DataZoneIdc connection string, the mutator returns it unchanged
- Cache TTLs are always positive and less than the credential lifetime
- Cache keys are unique per (user, step, identifiers) tuple

### Integration Testing Approach

- Use `moto` to mock the full AWS service chain (STS, SSO-OIDC, DataZone)
- Test the complete flow from mutator entry point to rewritten URI
- Test with realistic connection strings from `ConnectionStrings.md`
- Verify Redis caching behavior with a real Redis instance (via Docker)

## Performance Considerations

- **Caching strategy**: Multi-level caching ensures that the common case (all cached) requires only a single Redis GET for the final environment credentials
- **TTL buffer**: 60-second buffer before expiry prevents serving credentials that expire during query execution
- **Short-lived intermediary role**: The AssumeRoleWithWebIdentity step uses `DurationSeconds=900` (15 min) since it's only needed to call CreateTokenWithIAM
- **Connection pooling**: The Redis client is module-level (shared across requests) to avoid connection overhead
- **Lazy initialization**: boto3 clients are created only when needed (cache miss)
- **No blocking on cache write**: Redis SETEX is fire-and-forget for the happy path

## Security Considerations

- **Credential isolation**: Each user's credentials are cached under their email key — no cross-user leakage
- **No credentials in logs**: All logging redacts secret access keys and session tokens
- **Redis DB isolation**: Uses a dedicated Redis DB (db=2) separate from session store (db=0) and existing TIP cache (db=1)
- **Token validation**: Cognito tokens are checked for expiry before use (no signature verification needed — already validated at login)
- **HTTPS only**: The RedeemAccessToken REST call uses HTTPS exclusively
- **Environment variable secrets**: Role ARNs and application ARNs are not secrets, but the Cognito client secret and AWS credentials in `.env-local` must never be logged
- **Minimal permissions**: The intermediary role only needs `sso-oidc:CreateTokenWithIAM` — no broad IAM permissions

## Dependencies

| Dependency | Purpose | Already in Project |
|---|---|---|
| `boto3` | AWS SDK for STS, SSO-OIDC, DataZone API calls | Yes |
| `botocore` | Exception types (ClientError, BotoCoreError) | Yes (via boto3) |
| `redis` | Token/credential caching | Yes |
| `requests` | HTTP POST to DataZone RedeemAccessToken REST endpoint | Yes |
| `PyJWT` | Decode Cognito tokens to check expiry | Yes |
| `flask` | Session access for Cognito tokens | Yes |
| `flask-login` | Current user resolution | Yes |
| `sqlalchemy` | URL manipulation for connection rewriting | Yes |
