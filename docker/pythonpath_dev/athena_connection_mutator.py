# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

"""
DB_CONNECTION_MUTATOR for per-user Athena access via AWS Identity Center
Trusted Identity Propagation (TIP).

Flow:
  1. Intercept connections to Athena databases.
  2. Resolve the current Superset user's email from Flask-Login.
  3. Exchange the user's Cognito ID token for an Identity Center token
     via sso-oidc:CreateTokenWithIAM.
  4. Call STS AssumeRole with the Identity Center token in ProvidedContexts
     so that Lake Formation can resolve the user's identity for row- and
     column-level security enforcement.
  5. Rewrite the SQLAlchemy URI with the temporary credentials.

The STS and SSO-OIDC calls use whatever AWS credentials are available to
the process (host ~/.aws mounted into the container, instance profile,
or env vars).

Required environment variables (set in docker/.env-local):
  ATHENA_EXECUTION_ROLE_ARN   - ARN of the role to assume, e.g.:
                                arn:aws:iam::123456789012:role/my-execution-role
  IDC_APPLICATION_ARN         - Identity Center application ARN for
                                CreateTokenWithIAM, e.g.:
                                arn:aws:sso::123456789012:application/...
  ATHENA_S3_STAGING_DIR       - S3 path for Athena query results, e.g.:
                                s3://my-bucket/athena-results/
  AWS_REGION                  - AWS region, e.g.: eu-central-1
"""

import logging
import os
import re
import time
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError
import flask
from flask_login import current_user
import jwt
from redis import Redis
from sqlalchemy.engine.url import URL as SqlaURL

logger = logging.getLogger(__name__)

_ATHENA_DIALECT = re.compile(r"awsathena", re.IGNORECASE)

_EXECUTION_ROLE_ARN = os.environ.get("ATHENA_EXECUTION_ROLE_ARN", "")
_S3_STAGING_DIR = os.environ.get("ATHENA_S3_STAGING_DIR", "")
_AWS_REGION = os.environ.get("AWS_REGION", "eu-central-1")
_IDC_APPLICATION_ARN = os.environ.get("IDC_APPLICATION_ARN", "")

# Optional: role the IAM user must assume before it can call
# CreateTokenWithIAM and AssumeRole with ProvidedContexts.
# If set, the mutator will first assume this role using the ambient
# credentials and use the resulting session for all subsequent calls.
_SERVICE_ROLE_ARN = os.environ.get("SUPERSET_SERVICE_ROLE_ARN", "")

# Buffer in seconds — treat the token as expired a bit early to avoid races
_TOKEN_EXPIRY_BUFFER = 60

# Redis instance for sharing Cognito tokens between web and worker processes.
_token_redis = Redis(
    host=os.getenv("REDIS_HOST", "redis"),
    port=int(os.getenv("REDIS_PORT", "6379")),
    db=1,  # separate DB from session store (db=0)
)
_TOKEN_REDIS_PREFIX = "cognito_token:"
_TOKEN_REDIS_TTL = 3600  # 1 hour


def _store_cognito_tokens_in_redis(user_email: str) -> None:
    """Copy Cognito tokens from the Flask session to Redis for worker access."""
    id_token = flask.session.get("cognito_id_token")
    refresh_token = flask.session.get("cognito_refresh_token")
    username = flask.session.get("cognito_username", "")
    email = flask.session.get("cognito_email", "")
    if id_token:
        import json as _json
        data = _json.dumps({
            "cognito_id_token": id_token,
            "cognito_refresh_token": refresh_token or "",
            "cognito_username": username,
            "cognito_email": email,
        })
        _token_redis.setex(
            f"{_TOKEN_REDIS_PREFIX}{user_email}",
            _TOKEN_REDIS_TTL,
            data,
        )


def _get_cognito_tokens_from_redis(user_email: str) -> dict[str, str] | None:
    """Retrieve Cognito tokens from Redis (used by the Celery worker)."""
    raw = _token_redis.get(f"{_TOKEN_REDIS_PREFIX}{user_email}")
    if not raw:
        return None
    import json as _json
    return _json.loads(raw)

# Module-level cache for the assumed service-role session.
_service_session: boto3.Session | None = None
_service_session_expiry: float = 0


def _get_service_session() -> boto3.Session:
    """
    Return a boto3 Session with credentials from the assumed service role.

    If SUPERSET_SERVICE_ROLE_ARN is not set, returns the default session
    (ambient credentials). The assumed-role credentials are cached and
    refreshed when they approach expiry.
    """
    global _service_session, _service_session_expiry  # noqa: PLW0603

    if not _SERVICE_ROLE_ARN:
        return boto3.Session(region_name=_AWS_REGION)

    if _service_session and time.time() < _service_session_expiry:
        return _service_session

    logger.info("Assuming service role %s", _SERVICE_ROLE_ARN)
    sts = boto3.client("sts", region_name=_AWS_REGION)
    try:
        response = sts.assume_role(
            RoleArn=_SERVICE_ROLE_ARN,
            RoleSessionName="superset-service",
            DurationSeconds=3600,
        )
    except (BotoCoreError, ClientError):
        logger.exception("Failed to assume service role %s", _SERVICE_ROLE_ARN)
        raise RuntimeError(
            f"Could not assume service role {_SERVICE_ROLE_ARN}. "
            "Check the IAM user permissions and role trust policy."
        )


    creds = response["Credentials"]
    _service_session = boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=_AWS_REGION,
    )
    # Refresh 5 min before expiry
    _service_session_expiry = time.time() + 3300
    logger.info("Assumed service role, session valid for ~55 min")
    return _service_session


def _get_current_user_email() -> str | None:
    try:
        # In the web request context, flask_login.current_user is set.
        if current_user and not current_user.is_anonymous:
            return current_user.email or None
    except RuntimeError:
        pass
    # In the Celery worker context, Superset uses g.user via override_user.
    try:
        from flask import g
        user = getattr(g, "user", None)
        if user and not user.is_anonymous:
            return user.email or None
    except RuntimeError:
        pass
    return None


def _is_token_expired(token: str) -> bool:
    """Check if a JWT is expired (or about to expire within the buffer window)."""
    try:
        claims = jwt.decode(token, options={"verify_signature": False}, algorithms=["RS256"])
        exp = claims.get("exp")
        if exp is None:
            return True
        return time.time() >= (exp - _TOKEN_EXPIRY_BUFFER)
    except Exception:  # noqa: BLE001
        logger.warning("Could not decode token to check expiry — treating as expired")
        return True


def _compute_secret_hash(username: str, client_id: str, client_secret: str) -> str:
    """Compute the Cognito SECRET_HASH for the given username."""
    import base64
    import hashlib
    import hmac

    msg = username + client_id
    return base64.b64encode(
        hmac.new(
            client_secret.encode("utf-8"),
            msg.encode("utf-8"),
            hashlib.sha256,
        ).digest()
    ).decode("utf-8")


def _refresh_cognito_id_token(
    refresh_token: str | None = None,
    cognito_username: str | None = None,
    cognito_email: str | None = None,
    user_email_for_redis: str | None = None,
) -> str | None:
    """
    Use a refresh token to obtain a fresh Cognito ID token.

    When called without arguments, reads tokens from the Flask session
    (web context). Pass explicit values for the worker context (from Redis).

    Updates the Flask session (if available) and Redis with the new token.
    Returns the new ID token or None if refresh is not possible.
    """
    # Resolve parameters from Flask session when not explicitly provided
    if refresh_token is None:
        try:
            refresh_token = flask.session.get("cognito_refresh_token")
        except RuntimeError:
            pass
    if not refresh_token:
        logger.info("No refresh token available — cannot refresh Cognito ID token")
        return None

    if cognito_username is None:
        try:
            cognito_username = flask.session.get("cognito_username", "")
        except RuntimeError:
            cognito_username = ""
    if cognito_email is None:
        try:
            cognito_email = flask.session.get("cognito_email", "")
        except RuntimeError:
            cognito_email = ""

    client_id = os.environ.get("COGNITO_CLIENT_ID", "")
    client_secret = os.environ.get("COGNITO_CLIENT_SECRET", "")
    if not client_id:
        logger.warning("COGNITO_CLIENT_ID not set — cannot refresh token")
        return None

    candidates: list[str] = []
    if cognito_username:
        candidates.append(cognito_username)
    if cognito_email and cognito_email != cognito_username:
        candidates.append(cognito_email)

    if not candidates:
        logger.warning(
            "Neither cognito_username nor cognito_email available — "
            "cannot compute SECRET_HASH"
        )
        return None

    cognito_idp = boto3.client("cognito-idp", region_name=_AWS_REGION)

    for username_candidate in candidates:
        try:
            auth_params: dict[str, str] = {
                "REFRESH_TOKEN": refresh_token,
            }
            if client_secret:
                auth_params["SECRET_HASH"] = _compute_secret_hash(
                    username_candidate, client_id, client_secret
                )
            logger.debug(
                "Attempting token refresh with username=%s", username_candidate
            )

            response = cognito_idp.initiate_auth(
                ClientId=client_id,
                AuthFlow="REFRESH_TOKEN_AUTH",
                AuthParameters=auth_params,
            )
            result = response.get("AuthenticationResult", {})
            new_id_token = result.get("IdToken")
            if new_id_token:
                # Update Flask session if available
                try:
                    flask.session["cognito_id_token"] = new_id_token
                except RuntimeError:
                    pass
                # Update Redis so the worker picks up the fresh token
                email_key = user_email_for_redis or cognito_email
                if email_key:
                    import json as _json
                    data = _json.dumps({
                        "cognito_id_token": new_id_token,
                        "cognito_refresh_token": refresh_token,
                        "cognito_username": cognito_username or "",
                        "cognito_email": cognito_email or "",
                    })
                    _token_redis.setex(
                        f"{_TOKEN_REDIS_PREFIX}{email_key}",
                        _TOKEN_REDIS_TTL,
                        data,
                    )
                logger.info(
                    "Refreshed Cognito ID token via REFRESH_TOKEN_AUTH "
                    "(username=%s)",
                    username_candidate,
                )
                return new_id_token
        except ClientError as exc:
            error_code = exc.response.get("Error", {}).get("Code", "")
            if error_code == "NotAuthorizedException" and len(candidates) > 1:
                logger.info(
                    "SECRET_HASH rejected for username=%s, trying next candidate",
                    username_candidate,
                )
                continue
            logger.exception("Failed to refresh Cognito ID token")
            return None
        except BotoCoreError:
            logger.exception("Failed to refresh Cognito ID token")
            return None

    logger.error("All username candidates failed for SECRET_HASH computation")
    return None


def _get_cognito_id_token(user_email: str | None = None) -> str | None:
    """
    Read the Cognito ID token from the Flask session or Redis.

    In the web request context, reads from the Flask session.
    In the Celery worker context (no session), falls back to Redis.
    If the token is expired, attempt to refresh it using the stored refresh
    token. Returns None if no valid token is available.
    """
    # Try Flask session first (web request context)
    token = None
    try:
        token = flask.session.get("cognito_id_token")
    except RuntimeError:
        pass

    if token:
        if _is_token_expired(token):
            logger.info("Cognito ID token is expired — attempting refresh")
            token = _refresh_cognito_id_token()
        return token

    # Fall back to Redis (worker context)
    if user_email:
        redis_data = _get_cognito_tokens_from_redis(user_email)
        if redis_data:
            token = redis_data.get("cognito_id_token")
            if token and not _is_token_expired(token):
                logger.info("Retrieved Cognito ID token from Redis for %s", user_email)
                return token
            # Token expired — try refreshing using the refresh token from Redis
            logger.info("Cognito token from Redis is expired for %s — attempting refresh", user_email)
            token = _refresh_cognito_id_token(
                refresh_token=redis_data.get("cognito_refresh_token"),
                cognito_username=redis_data.get("cognito_username"),
                cognito_email=redis_data.get("cognito_email"),
                user_email_for_redis=user_email,
            )
            if token:
                return token

    return None


def _exchange_token_with_idc(id_token: str) -> str:
    """
    Exchange a Cognito ID token for an Identity Center token via
    sso-oidc:CreateTokenWithIAM.

    Returns the ``sts:identity_context`` claim extracted from the IDC
    ``idToken``.  This value (not the full JWT) is what STS AssumeRole
    expects in ``ProvidedContexts[].ContextAssertion``.
    """
    if not _IDC_APPLICATION_ARN:
        raise ValueError(
            "IDC_APPLICATION_ARN is not set — add it to docker/.env-local."
        )

    # Debug: log the Cognito token claims so we can verify iss/aud/exp
    try:
        claims = jwt.decode(id_token, options={"verify_signature": False}, algorithms=["RS256"])
        logger.info(
            "IDC exchange — Cognito token iss=%s  aud=%s  exp=%s  sub=%s  token_use=%s",
            claims.get("iss"),
            claims.get("aud"),
            claims.get("exp"),
            claims.get("sub"),
            claims.get("token_use"),
        )
    except Exception:  # noqa: BLE001
        logger.warning("IDC exchange — could not decode Cognito token for debug logging")

    sso_oidc = _get_service_session().client("sso-oidc", region_name=_AWS_REGION)
    logger.info(
        "IDC exchange — calling CreateTokenWithIAM with clientId=%s  region=%s",
        _IDC_APPLICATION_ARN,
        _AWS_REGION,
    )
    try:
        response = sso_oidc.create_token_with_iam(
            clientId=_IDC_APPLICATION_ARN,
            grantType="urn:ietf:params:oauth:grant-type:jwt-bearer",
            assertion=id_token,
        )
    except ClientError as exc:
        error_code = exc.response.get("Error", {}).get("Code", "")
        error_msg = exc.response.get("Error", {}).get("Message", "")
        logger.exception(
            "IDC token exchange failed — error=%s  message=%s  "
            "hint: if InvalidGrantException, verify that the Cognito ID "
            "token aud (%s) matches the Trusted Token Issuer audience "
            "and that the token is not expired (exp=%s)",
            error_code,
            error_msg,
            claims.get("aud", "unknown") if "claims" in dir() else "unknown",
            claims.get("exp", "unknown") if "claims" in dir() else "unknown",
        )
        raise RuntimeError(
            "Could not exchange Cognito token via Identity Center. "
            "Check the Identity Center Trusted Token Issuer configuration."
        )
    except BotoCoreError:
        logger.exception(
            "IDC token exchange failed — check the Identity Center "
            "Trusted Token Issuer configuration"
        )
        raise RuntimeError(
            "Could not exchange Cognito token via Identity Center. "
            "Check the Identity Center Trusted Token Issuer configuration."
        )

    idc_id_token = response["idToken"]

    # Extract the sts:identity_context claim from the IDC ID token.
    # STS AssumeRole ProvidedContexts.ContextAssertion has a 2048-char
    # limit, so we must pass only this claim — not the full JWT.
    try:
        idc_claims = jwt.decode(
            idc_id_token,
            options={"verify_signature": False},
            algorithms=["ES384", "RS256"],
        )
        identity_context = idc_claims.get("sts:identity_context")
        if not identity_context:
            logger.error(
                "IDC idToken does not contain sts:identity_context claim. "
                "Available claims: %s",
                list(idc_claims.keys()),
            )
            raise RuntimeError(
                "IDC idToken missing sts:identity_context claim. "
                "Check the Identity Center application configuration."
            )
        logger.info(
            "IDC exchange — extracted sts:identity_context (%d chars)",
            len(identity_context),
        )
        return identity_context
    except jwt.DecodeError:
        logger.exception("Could not decode IDC idToken JWT")
        raise RuntimeError("Could not decode IDC idToken to extract sts:identity_context.")


def _assume_role_with_idc_context(
    user_email: str, idc_context: str
) -> dict[str, str]:
    """
    Call STS AssumeRole with the Identity Center ``sts:identity_context``
    value in ProvidedContexts.

    ``idc_context`` must be the ``sts:identity_context`` claim extracted
    from the IDC idToken (not the full JWT), which fits within the 2048-char
    ContextAssertion limit.

    Returns a dict with ``aws_access_key_id``, ``aws_secret_access_key``,
    and ``aws_session_token``.
    """
    if not _EXECUTION_ROLE_ARN:
        raise ValueError(
            "ATHENA_EXECUTION_ROLE_ARN is not set — add it to docker/.env-local."
        )

    sts = _get_service_session().client("sts", region_name=_AWS_REGION)
    safe_name = re.sub(r"[^a-zA-Z0-9+=,.@-]", "-", user_email)[:64]

    try:
        response = sts.assume_role(
            RoleArn=_EXECUTION_ROLE_ARN,
            RoleSessionName=safe_name,
            ProvidedContexts=[
                {
                    "ProviderArn": "arn:aws:iam::aws:contextProvider/IdentityCenter",
                    "ContextAssertion": idc_context,
                }
            ],
            DurationSeconds=3600,
        )
        logger.info("Assumed role: %s", _EXECUTION_ROLE_ARN)
    except (BotoCoreError, ClientError):
        logger.exception(
            "STS AssumeRole with IDC context failed for %s — "
            "check the IAM trust policy",
            user_email,
        )
        raise RuntimeError(
            f"Could not assume role for {user_email}. "
            "Check the IAM trust policy."
        )

    creds = response["Credentials"]
    return {
        "aws_access_key_id": creds["AccessKeyId"],
        "aws_secret_access_key": creds["SecretAccessKey"],
        "aws_session_token": creds["SessionToken"],
    }


def athena_db_connection_mutator(
    uri: Any,
    connect_args: dict[str, Any],
    effective_username: str | None,
    security_manager: Any,
    source: str | None,
) -> tuple[Any, dict[str, Any]]:
    """
    Superset DB_CONNECTION_MUTATOR hook.

    Rewrites the Athena SQLAlchemy URI with per-user temporary credentials
    from STS AssumeRole, propagating the user's identity to Lake Formation.
    Non-Athena databases are returned unchanged.
    """
    uri_str = str(uri)
    if not _ATHENA_DIALECT.search(uri_str):
        return uri, connect_args

    logger.info(
        "athena_mutator: original URI=%s  database=%s  query=%s",
        uri_str,
        getattr(uri, "database", None),
        dict(getattr(uri, "query", {})),
    )

    user_email = _get_current_user_email()
    if not user_email:
        logger.warning(
            "athena_mutator: no authenticated user — falling back to ambient credentials"
        )
        return uri, connect_args

    # Get the Cognito ID token from the Flask session or Redis
    id_token = _get_cognito_id_token(user_email=user_email)

    # In web context, sync tokens to Redis so the Celery worker can use them
    try:
        if flask.session.get("cognito_id_token"):
            _store_cognito_tokens_in_redis(user_email)
    except RuntimeError:
        pass

    if not id_token:
        logger.warning(
            "athena_mutator: no Cognito ID token in session for %s "
            "— falling back to ambient credentials. "
            "Likely cause: tokens were not replicated to Redis at login. "
            "Ensure CognitoSecurityManager calls "
            "_store_cognito_tokens_in_redis() and the user re-authenticates.",
            user_email,
        )
        return uri, connect_args

    # Cache STS credentials, keyed by the Cognito ID token.
    # CreateTokenWithIAM with jwt-bearer grant may reject a token that has
    # already been exchanged, so we must avoid calling it twice with the
    # same assertion.  We also cache the STS creds to skip the AssumeRole
    # round-trip when the token hasn't changed.
    # Use Redis for caching so both web and worker processes can share.
    import json as _json
    cache_key = f"athena_creds:{user_email}"
    cached_raw = _token_redis.get(cache_key)
    cached = _json.loads(cached_raw) if cached_raw else {}
    cached_token = cached.get("id_token")
    cached_expiry = cached.get("expiry", 0)

    if cached_token == id_token and time.time() < cached_expiry:
        logger.info("athena_mutator: using cached STS credentials for %s", user_email)
        creds = cached
    else:
        # TIP flow: exchange Cognito token → IDC identity_context → STS creds
        idc_context = _exchange_token_with_idc(id_token)
        creds = _assume_role_with_idc_context(user_email, idc_context)
        # Cache for slightly less than the STS credential lifetime (1h)
        creds["id_token"] = id_token
        creds["expiry"] = time.time() + 3500  # ~58 min
        _token_redis.setex(cache_key, 3500, _json.dumps(creds))

    # Build query params for the new URL
    query_params: dict[str, str] = {
        "s3_staging_dir": _S3_STAGING_DIR,
        "aws_session_token": creds["aws_session_token"],
    }

    # Preserve non-credential query params from the original URI (e.g. catalog_name)
    # Read from the parsed URL object to avoid URL-encoding issues.
    original_query = dict(getattr(uri, "query", {}))
    for k, v in original_query.items():
        if k not in ("aws_access_key_id", "aws_secret_access_key",
                      "aws_session_token", "s3_staging_dir"):
            query_params[k] = v

    new_url = SqlaURL.create(
        drivername=getattr(uri, "drivername", "awsathena+rest"),
        username=creds["aws_access_key_id"],
        password=creds["aws_secret_access_key"],
        host=getattr(uri, "host", None),
        database=getattr(uri, "database", None),
        port=getattr(uri, "port", 443),
        query=query_params,
    )

    logger.info(
        "athena_mutator: rewrote URI for user %s — uri=%s",
        user_email,
        re.sub(r"://[^:]+:[^@]+@", "://***:***@", re.sub(r"(aws_session_token=)[^&]+", r"\1***", str(new_url)))
    )
    logger.info(
        "Connection arguments: \n %s",
        _json.dumps(connect_args, indent=2, default=str),
    )
    return new_url, connect_args
