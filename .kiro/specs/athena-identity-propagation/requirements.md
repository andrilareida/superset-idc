# Requirements Document

## Introduction

This feature enables Apache Superset to authenticate users via Amazon Cognito (OIDC) and propagate each user's identity to Amazon Athena queries through AWS IAM Identity Center's Trusted Identity Propagation (TIP). When a Superset user runs a query against an Athena database connection, the system exchanges the user's Cognito ID token for an Identity Center token via the `sso-oidc:CreateTokenWithIAM` API, then uses that token with `sts:AssumeRole` and the `ProvidedContexts` parameter to obtain temporary credentials that carry the user's Identity Center identity. This allows Lake Formation and Athena to enforce row-level and column-level security policies scoped to the individual user without session tags.

The implementation lives in the Docker-based development environment (`docker/pythonpath_dev/`) and consists of a custom Flask-AppBuilder security manager for Cognito OAuth, a `DB_CONNECTION_MUTATOR` hook that performs the Identity Center token exchange and rewrites Athena SQLAlchemy URIs with per-user STS credentials, and the supporting Docker Compose and dependency configuration.

## Glossary

- **Superset**: The Apache Superset web application, serving as the data visualization and SQL query platform.
- **Cognito_Provider**: The Amazon Cognito User Pool configured as an OIDC identity provider for Superset OAuth login.
- **Security_Manager**: The custom `CognitoSecurityManager` class that extends `SupersetSecurityManager` to map Cognito OIDC claims and group memberships to Superset user attributes and roles.
- **Connection_Mutator**: The `DB_CONNECTION_MUTATOR` hook function (`athena_db_connection_mutator`) that intercepts database connections and rewrites Athena URIs with per-user temporary credentials.
- **STS**: AWS Security Token Service, used to call `AssumeRole` with `ProvidedContexts` to obtain temporary credentials that carry the user's Identity Center identity.
- **Identity_Center**: AWS IAM Identity Center, the service that enables Trusted Identity Propagation (TIP) so that Athena and Lake Formation can enforce per-user access policies using the user's Identity Center identity directly.
- **TIP**: Trusted Identity Propagation — an Identity Center capability that allows a user's identity to flow through to downstream AWS services (Athena, Lake Formation) without session tags.
- **SSO_OIDC**: The `sso-oidc` AWS service used to exchange a Cognito ID token for an Identity Center token via the `CreateTokenWithIAM` API.
- **Identity_Center_Token**: A token issued by Identity Center after exchanging the Cognito ID token, representing the user's Identity Center identity.
- **ProvidedContexts**: An STS `AssumeRole` parameter that carries the Identity Center token context, enabling Lake Formation to resolve the user's identity for access control.
- **Lake_Formation**: AWS Lake Formation, the service that enforces row-level and column-level security on data accessed through Athena, using the Identity Center user identity propagated via TIP.
- **Athena_URI**: A SQLAlchemy connection string using the `awsathena+rest://` dialect to connect to Amazon Athena.
- **Execution_Role**: The IAM role ARN (`ATHENA_EXECUTION_ROLE_ARN`) that the Connection_Mutator assumes on behalf of each user via `sts:AssumeRole` with `ProvidedContexts`.
- **Trusted_Token_Issuer**: The Identity Center configuration that trusts the Cognito User Pool as an external identity provider for token exchange.

## Requirements

### Requirement 1: Cognito OIDC Authentication

**User Story:** As a Superset user, I want to log in using my Amazon Cognito credentials, so that I can access Superset without a separate local account.

#### Acceptance Criteria

1. WHEN a user navigates to the Superset login page, THE Superset SHALL redirect the user to the Cognito_Provider hosted UI for OIDC authentication.
2. WHEN the Cognito_Provider returns an authorization code to the callback URL `/oauth-authorized/cognito`, THE Security_Manager SHALL exchange the code for an access token and ID token.
3. WHEN a valid ID token is received, THE Security_Manager SHALL extract the user's email, given name, family name, and subject identifier from the OIDC claims.
4. WHEN the user's email is not already registered in Superset, THE Superset SHALL create a new user account with `AUTH_USER_REGISTRATION` enabled.
5. IF the ID token cannot be decoded or the OIDC claims are missing required fields (email, sub), THEN THE Security_Manager SHALL log a warning and deny the login attempt.

### Requirement 2: Cognito Group-to-Role Mapping

**User Story:** As a Superset administrator, I want Cognito group memberships to map to Superset roles, so that I can manage access control centrally in Cognito.

#### Acceptance Criteria

1. WHEN a user logs in, THE Security_Manager SHALL extract the `cognito:groups` claim from the ID token.
2. WHEN the `cognito:groups` claim is not present in the userinfo response, THE Security_Manager SHALL decode the raw ID token (without signature verification, since Authlib has already validated the token) to extract the groups.
3. WHEN a Cognito group name matches an entry in `COGNITO_GROUP_ROLE_MAP`, THE Security_Manager SHALL assign the corresponding Superset role to the user.
4. WHEN no Cognito group matches any entry in `COGNITO_GROUP_ROLE_MAP`, THE Security_Manager SHALL assign the default role (`Gamma`) to the user.
5. THE Security_Manager SHALL re-synchronize the user's roles on every login when `AUTH_ROLES_SYNC_AT_LOGIN` is enabled.

### Requirement 3: Per-User Athena Credential Injection via Trusted Identity Propagation

**User Story:** As a Superset user, I want my Athena queries to run under my own identity, so that Lake Formation row-level and column-level security policies apply to my data access.

#### Acceptance Criteria

1. WHEN a database connection uses the `awsathena` SQLAlchemy dialect, THE Connection_Mutator SHALL intercept the connection before query execution.
2. WHEN an authenticated user is present in the Flask session, THE Security_Manager SHALL store the Cognito ID token from the OAuth response so that the Connection_Mutator can access it later.
3. THE Connection_Mutator SHALL exchange the user's Cognito ID token for an Identity Center token by calling the `sso-oidc:CreateTokenWithIAM` API with `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer` and the `assertion` set to the Cognito ID token.
4. THE Connection_Mutator SHALL call STS `AssumeRole` using the configured `ATHENA_EXECUTION_ROLE_ARN` with the `ProvidedContexts` parameter set to the Identity Center token context, so that Lake Formation can resolve the user's identity for access control.
5. WHEN the STS `AssumeRole` call succeeds, THE Connection_Mutator SHALL rewrite the Athena_URI with the temporary `aws_access_key_id`, `aws_secret_access_key`, and `aws_session_token` credentials.
6. THE Connection_Mutator SHALL URL-encode all credential values and query parameters embedded in the rewritten Athena_URI.
7. WHEN the original Athena_URI contains non-credential query parameters (such as schema or catalog), THE Connection_Mutator SHALL preserve those parameters in the rewritten URI.

### Requirement 4: STS Session Name Safety

**User Story:** As a system operator, I want STS session names to be safe and traceable, so that CloudTrail logs show which user initiated each Athena query.

#### Acceptance Criteria

1. THE Connection_Mutator SHALL derive the STS `RoleSessionName` from the user's email address.
2. THE Connection_Mutator SHALL replace characters not allowed in STS session names (characters outside `[a-zA-Z0-9+=,.@-]`) with a hyphen (`-`).
3. THE Connection_Mutator SHALL truncate the sanitized session name to a maximum of 64 characters.

### Requirement 5: Graceful Fallback for Unauthenticated Connections

**User Story:** As a system operator, I want Athena connections to fall back to ambient AWS credentials when no user is authenticated, so that background tasks and health checks do not fail.

#### Acceptance Criteria

1. WHEN no authenticated user is present in the Flask session (anonymous or missing user), THE Connection_Mutator SHALL return the original URI and connect_args unchanged.
2. WHEN no authenticated user is present, THE Connection_Mutator SHALL log a warning indicating the fallback to ambient credentials.
3. WHEN the database connection does not use the `awsathena` dialect, THE Connection_Mutator SHALL return the original URI and connect_args unchanged without any modification.

### Requirement 6: Token Exchange and STS Error Handling

**User Story:** As a Superset user, I want a clear error message when Athena credential retrieval fails, so that I can report the issue to my administrator.

#### Acceptance Criteria

1. IF the `ATHENA_EXECUTION_ROLE_ARN` environment variable is not set, THEN THE Connection_Mutator SHALL raise a `ValueError` with a message referencing the missing variable.
2. IF the `IDC_APPLICATION_ARN` environment variable is not set, THEN THE Connection_Mutator SHALL raise a `ValueError` with a message referencing the missing variable.
3. IF the `sso-oidc:CreateTokenWithIAM` call fails with a `BotoCoreError` or `ClientError`, THEN THE Connection_Mutator SHALL raise a `RuntimeError` with a message that includes the user's email and a reference to the Identity Center Trusted Token Issuer configuration.
4. IF the STS `AssumeRole` call fails with a `BotoCoreError` or `ClientError`, THEN THE Connection_Mutator SHALL raise a `RuntimeError` with a message that includes the user's email and a reference to the IAM trust policy.
5. IF any AWS API call in the token exchange flow fails, THEN THE Connection_Mutator SHALL log the full exception traceback at the exception level.
6. IF the user's Cognito ID token is not available in the session, THEN THE Connection_Mutator SHALL log a warning and fall back to ambient credentials.

### Requirement 7: Docker Environment Configuration

**User Story:** As a developer, I want the Docker Compose environment to be pre-configured for Cognito authentication and Athena identity propagation, so that I can run the feature locally with minimal setup.

#### Acceptance Criteria

1. THE docker-compose.yml SHALL mount the host `~/.aws` directory as a read-only volume at `/root/.aws` in the Superset container so that STS and SSO-OIDC can use host AWS credentials.
2. THE docker-compose.yml SHALL pass `COGNITO_CLIENT_ID`, `COGNITO_CLIENT_SECRET`, and `SUPERSET_PUBLIC_URL` as environment variables to the `superset`, `superset-init`, and `superset-worker` services.
3. THE `superset_config_docker.py` SHALL set `AUTH_TYPE` to `AUTH_OAUTH` and configure the Cognito OIDC provider with the `server_metadata_url` pointing to the Cognito User Pool's `.well-known/openid-configuration` endpoint.
4. THE `superset_config_docker.py` SHALL set `DB_CONNECTION_MUTATOR` to the `athena_db_connection_mutator` function.
5. THE `requirements-local.txt` SHALL include `PyAthena[SQLAlchemy]>=3.0.0` as a dependency for the Athena SQLAlchemy dialect.
6. THE `superset_config_docker.py` SHALL set `CUSTOM_SECURITY_MANAGER` to the `CognitoSecurityManager` class.
7. THE docker environment SHALL support the `IDC_APPLICATION_ARN` environment variable for the Identity Center application ARN used in the `CreateTokenWithIAM` call.

### Requirement 8: Credential Scoping and Identity Propagation

**User Story:** As a security engineer, I want each user's Athena session to carry their Identity Center identity and be time-limited, so that credentials cannot be reused beyond their intended scope and Lake Formation can enforce per-user policies.

#### Acceptance Criteria

1. THE Connection_Mutator SHALL request STS temporary credentials with a `DurationSeconds` value of 3600 (one hour).
2. THE Connection_Mutator SHALL use a unique `RoleSessionName` per user so that each user's session is independently identifiable in CloudTrail.
3. THE Connection_Mutator SHALL pass the Identity Center token context via the `ProvidedContexts` parameter in the STS `AssumeRole` call, so that the user's Identity Center identity is propagated to Athena and Lake Formation.
