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
DB_CONNECTION_MUTATOR for per-user Athena access via Amazon DataZone
Identity Center (IDC) credential flow.

Flow:
  1. Intercept connections to Athena databases where
     CredentialsProvider=DataZoneIdc is set in the connection string.
  2. Resolve the current Superset user's email from Flask-Login or
     the Celery worker context (flask.g.user).
  3. Exchange the user's Cognito ID token for DataZone environment
     credentials through a multi-step token chain:
       Cognito → STS AssumeRoleWithWebIdentity
       → SSO-OIDC CreateTokenWithIAM
       → DataZone RedeemAccessToken (REST)
       → DataZone GetEnvironmentCredentials
  4. Rewrite the SQLAlchemy URI with the per-user environment
     credentials so PyAthena connects on behalf of the user.

Each step is cached via Flask-Caching (Superset's cache_manager) with
appropriate TTLs to avoid repeating the full chain on every query.

Required environment variables (set in docker/.env-local):
  OIDC_ROLE_ARN           - IAM role trusted by the Cognito identity
                            provider for AssumeRoleWithWebIdentity.
  IDC_APPLICATION_ARN     - Identity Center application ARN for
                            CreateTokenWithIAM.
  DATAZONE_DOMAIN_ID      - Default DataZone domain identifier
                            (fallback when not in connection string).
  DATAZONE_ENVIRONMENT_ID - Default DataZone environment identifier
                            (fallback when not in connection string).
  AWS_REGION              - AWS region (default: eu-central-1).
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError
import flask
import requests
from flask_login import current_user
import jwt
from sqlalchemy.engine.url import URL as SqlaURL

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Environment variables
# ---------------------------------------------------------------------------

OIDC_ROLE_ARN: str = os.environ.get("OIDC_ROLE_ARN", "")
IDC_APPLICATION_ARN: str = os.environ.get("IDC_APPLICATION_ARN", "")
DATAZONE_DOMAIN_ID: str = os.environ.get("DATAZONE_DOMAIN_ID", "")
DATAZONE_ENVIRONMENT_ID: str = os.environ.get("DATAZONE_ENVIRONMENT_ID", "")
AWS_REGION: str = os.environ.get("AWS_REGION", "eu-central-1")

# Regex to match the Athena dialect in the SQLAlchemy drivername
_ATHENA_DIALECT = re.compile(r"awsathena", re.IGNORECASE)

# Buffer in seconds — treat the token as expired a bit early to avoid races
_TOKEN_EXPIRY_BUFFER = 60

# Cache key prefix and TTL for Cognito tokens shared between web/worker
_TOKEN_CACHE_PREFIX = "cognito_tokens:"
_TOKEN_CACHE_TTL = 3600  # 1 hour


# ---------------------------------------------------------------------------
# Cognito token helpers (using Flask-Caching via _cache_get / _cache_set)
# ---------------------------------------------------------------------------


def _store_cognito_tokens(user_email: str) -> None:
    """Copy Cognito tokens from the Flask session to cache for worker access."""
    id_token = flask.session.get("cognito_id_token")
    refresh_token = flask.session.get("cognito_refresh_token")
    username = flask.session.get("cognito_username", "")
    email = flask.session.get("cognito_email", "")
    if id_token:
        _cache_set(
            f"{_TOKEN_CACHE_PREFIX}{user_email}",
            {
                "cognito_id_token": id_token,
                "cognito_refresh_token": refresh_token or "",
                "cognito_username": username,
                "cognito_email": email,
            },
            ttl_seconds=_TOKEN_CACHE_TTL,
        )


def _get_cognito_tokens(user_email: str) -> dict[str, str] | None:
    """Retrieve Cognito tokens from cache (used by the Celery worker)."""
    return _cache_get(f"{_TOKEN_CACHE_PREFIX}{user_email}")


def _is_token_expired(token: str) -> bool:
    """Check if a JWT is expired (or about to expire within the buffer window)."""
    try:
        claims = jwt.decode(
            token, options={"verify_signature": False}, algorithms=["RS256"]
        )
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
    user_email_for_cache: str | None = None,
) -> str | None:
    """Use a refresh token to obtain a fresh Cognito ID token.

    When called without arguments, reads tokens from the Flask session
    (web context). Pass explicit values for the worker context (from cache).

    Updates the Flask session (if available) and cache with the new token.
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

    cognito_idp = boto3.client("cognito-idp", region_name=AWS_REGION)

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
                # Update cache so the worker picks up the fresh token
                email_key = user_email_for_cache or cognito_email
                if email_key:
                    _cache_set(
                        f"{_TOKEN_CACHE_PREFIX}{email_key}",
                        {
                            "cognito_id_token": new_id_token,
                            "cognito_refresh_token": refresh_token,
                            "cognito_username": cognito_username or "",
                            "cognito_email": cognito_email or "",
                        },
                        ttl_seconds=_TOKEN_CACHE_TTL,
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


# ---------------------------------------------------------------------------
# Flask-Caching helpers for DataZone credential caching
#
# Uses Superset's cache_manager.cache (configured via CACHE_CONFIG) which
# supports any Flask-Caching backend (Redis, Memcached, filesystem, etc.).
# Serialization is handled by Flask-Caching (pickle) so datetime objects
# and other Python types are stored without manual JSON conversion.
# ---------------------------------------------------------------------------


def _get_flask_cache():
    """Lazily import and return the Flask-Caching cache instance.

    Returns the cache_manager.cache instance when a Flask app context is
    available, or None if the import fails or no app context exists.
    """
    try:
        from superset.extensions import cache_manager
        return cache_manager.cache
    except Exception:  # noqa: BLE001
        return None


# ---------------------------------------------------------------------------
# Caching helpers (using Flask-Caching via Superset's cache_manager)
# ---------------------------------------------------------------------------


def _cache_get(cache_key: str) -> dict[str, Any] | None:
    """Retrieve a cached value, returning None on miss or error.

    Implements graceful degradation: if the cache backend is unavailable
    or the stored value cannot be retrieved, logs a warning and returns
    None so the caller proceeds without caching.

    Args:
        cache_key: Cache key (e.g. "dz_mutator:intermediary:user@ex.com:abc123").

    Returns:
        Cached dict on hit, or None on miss/error.
    """
    try:
        cache = _get_flask_cache()
        if cache is None:
            return None
        return cache.get(cache_key)
    except Exception:  # noqa: BLE001
        logger.warning(
            "datazone_mutator: cache GET failed for key=%s — "
            "proceeding without cache",
            cache_key,
        )
        return None


def _cache_set(cache_key: str, value: dict[str, Any], ttl_seconds: int) -> None:
    """Store a value in the cache with the given TTL (seconds).

    Implements graceful degradation: if the cache backend is unavailable,
    logs a warning and returns without raising.

    Args:
        cache_key: Cache key.
        value: Dict to store.
        ttl_seconds: Time-to-live in seconds. If <= 0, the value is not cached.
    """
    if ttl_seconds <= 0:
        return
    try:
        cache = _get_flask_cache()
        if cache is None:
            logger.warning(
                "datazone_mutator: cache unavailable for SET key=%s — "
                "proceeding without cache",
                cache_key,
            )
            return
        cache.set(cache_key, value, timeout=ttl_seconds)
    except Exception:  # noqa: BLE001
        logger.warning(
            "datazone_mutator: cache SET failed for key=%s — "
            "proceeding without cache",
            cache_key,
        )


def _invalidate_cache_entry(cache_key: str) -> None:
    """Delete a cache entry, logging the invalidation.

    Implements graceful degradation: if the cache backend is unavailable,
    logs a warning and returns without raising.

    Args:
        cache_key: The cache key to delete.

    Returns:
        None
    """
    try:
        cache = _get_flask_cache()
        if cache is None:
            logger.warning(
                "datazone_mutator: cache unavailable for DELETE key=%s — "
                "proceeding without invalidation",
                cache_key,
            )
            return None
        cache.delete(cache_key)
        logger.info(
            "datazone_mutator: invalidated cache entry key=%s",
            cache_key,
        )
    except Exception:  # noqa: BLE001
        logger.warning(
            "datazone_mutator: cache DELETE failed for key=%s — "
            "proceeding without invalidation",
            cache_key,
        )
    return None


def _build_cache_key(step: str, user_email: str, *identifiers: str) -> str:
    """Build a namespaced cache key for the DataZone credential chain.

    Key format: ``dz_mutator:{step}:{user_email}:{identifier_hash}``

    The identifier hash is a truncated SHA-256 (16 hex chars) of the
    concatenated identifiers, providing a fixed-length suffix regardless
    of how many or how long the identifiers are.

    Args:
        step: Cache step name (e.g. "intermediary", "idc_token",
            "domain_creds", "env_creds").
        user_email: Current user's email address.
        *identifiers: One or more strings to hash (e.g. role ARN,
            domain ID, environment ID).

    Returns:
        Cache key string.
    """
    raw = ":".join(identifiers)
    identifier_hash = hashlib.sha256(raw.encode()).hexdigest()[:16]
    return f"dz_mutator:{step}:{user_email}:{identifier_hash}"


def _compute_expiration_ttl(expiration: Any, buffer: int | None = None) -> int:
    """Compute a cache TTL from an expiration value with a configurable buffer.

    Handles expiration values as:
      - Unix timestamp (int or float)
      - ISO 8601 datetime string (e.g. "2024-01-15T12:00:00Z")
      - datetime object

    Returns the number of seconds until expiration minus the buffer.
    Returns 0 if the expiration cannot be parsed or the TTL would be <= 0.

    Args:
        expiration: Expiration value (timestamp, ISO string, or datetime).
        buffer: Safety buffer in seconds. Defaults to _get_ttl_buffer() if None.

    Returns:
        TTL in seconds (>= 0). Returns 0 if caching should be skipped.
    """
    if buffer is None:
        buffer = _get_ttl_buffer()
    try:
        if isinstance(expiration, (int, float)):
            expiration_epoch = float(expiration)
        elif isinstance(expiration, str):
            # Try parsing as ISO 8601 datetime string
            # Handle both "Z" suffix and "+00:00" timezone formats
            exp_str = expiration.replace("Z", "+00:00")
            dt = datetime.fromisoformat(exp_str)
            expiration_epoch = dt.timestamp()
        elif hasattr(expiration, "timestamp"):
            # datetime object
            expiration_epoch = expiration.timestamp()
        else:
            return 0

        ttl = int(expiration_epoch - time.time() - buffer)
        return max(ttl, 0)
    except (ValueError, TypeError, OSError):
        return 0


def _get_ttl_buffer() -> int:
    """Read the TTL buffer from CREDENTIAL_CACHE_TTL_BUFFER env var.

    Returns:
        Buffer in seconds. Defaults to 60 if env var is unset or invalid.
    """
    raw = os.environ.get("CREDENTIAL_CACHE_TTL_BUFFER")
    if not raw:
        return 60
    try:
        return int(raw)
    except (ValueError, TypeError):
        logger.warning(
            "datazone_mutator: CREDENTIAL_CACHE_TTL_BUFFER=%r is not a valid "
            "integer - defaulting to 60 seconds",
            raw,
        )
        return 60


def _is_credential_expired(cached_entry: dict[str, Any], ttl_buffer: int) -> bool:
    """Check if a cached credential entry has expired or is about to expire.

    Args:
        cached_entry: Dict containing an 'expiration' field (Unix timestamp,
            ISO 8601 string, or datetime object).
        ttl_buffer: Safety buffer in seconds to subtract from expiration.

    Returns:
        True if credentials are expired or will expire within the buffer window.
    """
    expiration = cached_entry.get("expiration")
    if expiration is None:
        logger.debug(
            "datazone_mutator: cached entry has no 'expiration' field - "
            "treating as expired"
        )
        return True

    try:
        if isinstance(expiration, (int, float)):
            expiration_epoch = float(expiration)
        elif isinstance(expiration, str):
            exp_str = expiration.replace("Z", "+00:00")
            dt = datetime.fromisoformat(exp_str)
            expiration_epoch = dt.timestamp()
        elif hasattr(expiration, "timestamp"):
            # datetime object
            expiration_epoch = expiration.timestamp()
        else:
            logger.debug(
                "datazone_mutator: unparseable expiration type=%s - "
                "treating as expired",
                type(expiration).__name__,
            )
            return True
    except (ValueError, TypeError, OSError):
        logger.debug(
            "datazone_mutator: failed to parse expiration value - "
            "treating as expired"
        )
        return True

    remaining = expiration_epoch - time.time() - ttl_buffer
    return remaining <= 0


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class DataZoneConnectionParams:
    """Parameters extracted from a DataZoneIdc connection string."""

    domain_id: str
    environment_id: str
    domain_region: str
    identity_center_issuer_url: str
    workgroup: str


# ---------------------------------------------------------------------------
# Connection string parsing (Task 1.2)
# ---------------------------------------------------------------------------


def parse_datazone_params(uri: SqlaURL) -> DataZoneConnectionParams | None:
    """
    Extract DataZone parameters from the connection string query params.

    Returns None if this is not a DataZoneIdc connection (i.e.
    CredentialsProvider != DataZoneIdc, case-insensitive).

    Falls back to environment variables for missing parameters.
    Logs an error and returns None if required params (domain_id,
    environment_id) are missing from both the URI and env vars.
    """
    query_params: dict[str, Any] = dict(getattr(uri, "query", {}))

    # Check for CredentialsProvider=DataZoneIdc (case-insensitive value)
    credentials_provider = query_params.get("CredentialsProvider", "")
    if credentials_provider.lower() != "datazoneidc":
        return None

    # Extract parameters from query string with env var fallbacks
    domain_id = query_params.get("DataZoneDomainId", "") or DATAZONE_DOMAIN_ID
    environment_id = (
        query_params.get("DataZoneEnvironmentId", "") or DATAZONE_ENVIRONMENT_ID
    )
    domain_region = query_params.get("region_name", "") or AWS_REGION
    identity_center_issuer_url = query_params.get("IdentityCenterIssuerUrl", "")
    workgroup = query_params.get("work_group", "") or query_params.get("Workgroup", "")

    # Validate required parameters
    if not domain_id:
        logger.error(
            "DataZone connection missing required parameter 'domain_id'. "
            "Set DataZoneDomainId in the connection string or "
            "DATAZONE_DOMAIN_ID environment variable."
        )
        return None

    if not environment_id:
        logger.error(
            "DataZone connection missing required parameter 'environment_id'. "
            "Set DataZoneEnvironmentId in the connection string or "
            "DATAZONE_ENVIRONMENT_ID environment variable."
        )
        return None

    return DataZoneConnectionParams(
        domain_id=domain_id,
        environment_id=environment_id,
        domain_region=domain_region,
        identity_center_issuer_url=identity_center_issuer_url,
        workgroup=workgroup,
    )


# ---------------------------------------------------------------------------
# User context resolution (Task 1.4)
# ---------------------------------------------------------------------------


def _get_current_user_email() -> str | None:
    """
    Resolve the current user's email from Flask-Login or Celery context.

    In the web request context, flask_login.current_user is set.
    In the Celery worker context, Superset uses flask.g.user via
    override_user.

    Returns None if no authenticated user can be resolved.
    """
    try:
        if current_user and not current_user.is_anonymous:
            return current_user.email or None
    except RuntimeError:
        pass
    try:
        from flask import g

        user = getattr(g, "user", None)
        if user and not user.is_anonymous:
            return user.email or None
    except RuntimeError:
        pass
    return None


# ---------------------------------------------------------------------------
# Cognito token retrieval (Task 2.2 – 2.4)
# ---------------------------------------------------------------------------


def _get_cognito_id_token(user_email: str) -> str | None:
    """
    Read the Cognito ID token from the Flask session or cache.

    In the web request context, reads from the Flask session.
    In the Celery worker context (no session), falls back to the cache
    via ``_get_cognito_tokens``.

    If the token is expired (checked with a 60-second buffer via
    ``_is_token_expired``), attempts a refresh using the stored
    refresh token via ``_refresh_cognito_id_token``.

    Returns the valid ID token string, or None if no token is
    available and refresh is not possible.
    """
    # Try Flask session first (web request context)
    token: str | None = None
    try:
        token = flask.session.get("cognito_id_token")
    except RuntimeError:
        pass

    if token:
        if _is_token_expired(token):
            logger.info(
                "datazone_mutator: Cognito ID token from session is expired "
                "— attempting refresh for %s",
                user_email,
            )
            token = _refresh_cognito_id_token(user_email_for_cache=user_email)
        if token:
            # Sync tokens to cache so Celery workers can use them
            try:
                _store_cognito_tokens(user_email)
            except Exception:  # noqa: BLE001
                logger.debug(
                    "datazone_mutator: could not sync tokens to cache for %s",
                    user_email,
                )
            return token

    # Fall back to cache (worker context)
    cached_data = _get_cognito_tokens(user_email)
    if cached_data:
        token = cached_data.get("cognito_id_token")
        if token and not _is_token_expired(token):
            logger.info(
                "datazone_mutator: retrieved valid Cognito ID token from "
                "cache for %s",
                user_email,
            )
            return token
        # Token expired — try refreshing using the refresh token from cache
        logger.info(
            "datazone_mutator: Cognito token from cache is expired for %s "
            "— attempting refresh",
            user_email,
        )
        token = _refresh_cognito_id_token(
            refresh_token=cached_data.get("cognito_refresh_token"),
            cognito_username=cached_data.get("cognito_username"),
            cognito_email=cached_data.get("cognito_email"),
            user_email_for_cache=user_email,
        )
        if token:
            return token

    return None


# ---------------------------------------------------------------------------
# Token exchange chain — Step 1 & Step 2 (Task 3)
# ---------------------------------------------------------------------------


def _assume_role_with_web_identity(
    cognito_id_token: str, oidc_role_arn: str, user_email: str
) -> dict[str, str]:
    """Step 1: AssumeRoleWithWebIdentity → intermediary IAM credentials.

    Exchanges the Cognito ID token for short-lived IAM credentials by
    assuming the OIDC-trusted role. These intermediary credentials are
    used in Step 2 to call SSO-OIDC CreateTokenWithIAM.

    Results are cached with TTL=850s (900s role duration minus
    50s buffer).

    Args:
        cognito_id_token: Valid Cognito ID token JWT.
        oidc_role_arn: IAM role ARN trusted by the Cognito identity provider.
        user_email: Current user's email (used for RoleSessionName and cache key).

    Returns:
        Dict with keys: AccessKeyId, SecretAccessKey, SessionToken.

    Raises:
        RuntimeError: If STS rejects the request (trust policy mismatch,
            token audience mismatch, etc.).
    """
    # Check cache first
    cache_key = _build_cache_key("intermediary", user_email, oidc_role_arn)
    cached = _cache_get(cache_key)
    if cached is not None:
        logger.debug(
            "Step 1 (AssumeRoleWithWebIdentity) cache hit for user=%s",
            user_email,
        )
        return cached

    # Sanitize user email for RoleSessionName:
    # Max 64 chars, valid characters: alphanumeric, =,.@-
    session_name = re.sub(r"[^a-zA-Z0-9=,.@\-]", "-", user_email)[:64]

    sts_client = boto3.client("sts", region_name=AWS_REGION)

    try:
        response = sts_client.assume_role_with_web_identity(
            RoleArn=oidc_role_arn,
            RoleSessionName=session_name,
            WebIdentityToken=cognito_id_token,
            DurationSeconds=900,
        )
    except (BotoCoreError, ClientError) as exc:
        # Extract error code for debugging
        error_code = "Unknown"
        if isinstance(exc, ClientError):
            error_code = exc.response.get("Error", {}).get("Code", "Unknown")

        # Log role ARN and token issuer for debugging
        token_issuer = "unknown"
        try:
            claims = jwt.decode(
                cognito_id_token,
                options={"verify_signature": False},
                algorithms=["RS256"],
            )
            token_issuer = claims.get("iss", "unknown")
        except Exception:  # noqa: BLE001
            pass

        logger.error(
            "Step 1 (AssumeRoleWithWebIdentity) failed — "
            "error_code=%s  role_arn=%s  token_issuer=%s  user=%s",
            error_code,
            oidc_role_arn,
            token_issuer,
            user_email,
        )
        raise RuntimeError(
            f"AssumeRoleWithWebIdentity failed with error '{error_code}' "
            f"for role {oidc_role_arn}. Verify the role trust policy "
            f"includes the Cognito user pool as a trusted identity provider."
        ) from exc

    creds = response["Credentials"]
    result = {
        "AccessKeyId": creds["AccessKeyId"],
        "SecretAccessKey": creds["SecretAccessKey"],
        "SessionToken": creds["SessionToken"],
    }

    # Cache with TTL=850s (900s duration - 50s buffer)
    _cache_set(cache_key, result, ttl_seconds=850)

    return result


def _create_token_with_iam(
    cognito_id_token: str,
    intermediary_creds: dict[str, str],
    idc_application_arn: str,
    user_email: str,
) -> dict[str, str]:
    """Step 2: CreateTokenWithIAM → IDC access token and expires_in.

    Uses the intermediary IAM credentials from Step 1 to call SSO-OIDC
    CreateTokenWithIAM, exchanging the Cognito ID token for an Identity
    Center access token.

    Results are cached with TTL = expiresIn - 60s.

    Args:
        cognito_id_token: Valid Cognito ID token JWT (used as assertion).
        intermediary_creds: Dict with AccessKeyId, SecretAccessKey,
            SessionToken from Step 1.
        idc_application_arn: Identity Center application ARN (clientId).
        user_email: Current user's email (used for cache key).

    Returns:
        Dict with keys: access_token, expires_in.

    Raises:
        RuntimeError: If the IDC application rejects the token or any
            other SSO-OIDC error occurs.
    """
    # Check cache first
    cache_key = _build_cache_key("idc_token", user_email, idc_application_arn)
    cached = _cache_get(cache_key)
    if cached is not None:
        logger.debug(
            "Step 2 (CreateTokenWithIAM) cache hit for user=%s",
            user_email,
        )
        return cached

    # Create a boto3 session using the intermediary credentials
    session = boto3.Session(
        aws_access_key_id=intermediary_creds["AccessKeyId"],
        aws_secret_access_key=intermediary_creds["SecretAccessKey"],
        aws_session_token=intermediary_creds["SessionToken"],
        region_name=AWS_REGION,
    )
    sso_oidc = session.client("sso-oidc", region_name=AWS_REGION)

    try:
        response = sso_oidc.create_token_with_iam(
            clientId=idc_application_arn,
            grantType="urn:ietf:params:oauth:grant-type:jwt-bearer",
            assertion=cognito_id_token,
        )
    except ClientError as exc:
        error_code = exc.response.get("Error", {}).get("Code", "Unknown")

        if error_code == "InvalidGrantException":
            # Log Cognito token claims for debugging
            token_claims: dict[str, str] = {}
            try:
                claims = jwt.decode(
                    cognito_id_token,
                    options={"verify_signature": False},
                    algorithms=["RS256"],
                )
                token_claims = {
                    "iss": str(claims.get("iss", "")),
                    "aud": str(claims.get("aud", "")),
                    "exp": str(claims.get("exp", "")),
                }
            except Exception:  # noqa: BLE001
                token_claims = {"decode_error": "could not decode token"}

            logger.error(
                "Step 2 (CreateTokenWithIAM) InvalidGrantException — "
                "idc_app_arn=%s  cognito_claims=%s  "
                "hint: verify the Trusted Token Issuer audience matches "
                "the Cognito token 'aud' claim and the token is not expired",
                idc_application_arn,
                token_claims,
            )
            raise RuntimeError(
                f"CreateTokenWithIAM failed with InvalidGrantException "
                f"for IDC application {idc_application_arn}. "
                f"Verify the Trusted Token Issuer configuration matches "
                f"the Cognito user pool issuer and audience."
            ) from exc

        # Other ClientError
        logger.error(
            "Step 2 (CreateTokenWithIAM) failed — "
            "error_code=%s  idc_app_arn=%s",
            error_code,
            idc_application_arn,
        )
        raise RuntimeError(
            f"CreateTokenWithIAM failed with error '{error_code}' "
            f"for IDC application {idc_application_arn}."
        ) from exc
    except BotoCoreError as exc:
        logger.error(
            "Step 2 (CreateTokenWithIAM) BotoCoreError — "
            "idc_app_arn=%s  error=%s",
            idc_application_arn,
            exc,
        )
        raise RuntimeError(
            f"CreateTokenWithIAM failed for IDC application "
            f"{idc_application_arn}: {exc}"
        ) from exc

    access_token = response["accessToken"]
    expires_in = response.get("expiresIn", 0)

    logger.info(
        "Step 2 (CreateTokenWithIAM) succeeded — "
        "idc_app_arn=%s  expires_in=%s",
        idc_application_arn,
        expires_in,
    )

    result = {
        "access_token": access_token,
        "expires_in": expires_in,
    }

    # Cache with TTL = expiresIn - 60s
    ttl = int(expires_in) - 60 if expires_in else 0
    _cache_set(cache_key, result, ttl_seconds=ttl)

    return result


# ---------------------------------------------------------------------------
# Token exchange chain — Step 3 & Step 4 (Task 4)
# ---------------------------------------------------------------------------


def _redeem_access_token(
    idc_access_token: str, domain_id: str, region: str, user_email: str
) -> dict[str, str]:
    """Step 3: RedeemAccessToken → DomainExecutionRole credentials.

    Sends an HTTP POST to the DataZone SSO redeem-token endpoint to
    exchange the IDC access token for DomainExecutionRole credentials.

    Results are cached with TTL based on the expiration field
    minus a 60-second buffer.

    Args:
        idc_access_token: Valid IDC access token from CreateTokenWithIAM.
        domain_id: DataZone domain identifier (e.g., "dzd-...").
        region: AWS region for the DataZone domain.
        user_email: Current user's email (used for cache key).

    Returns:
        Dict with keys: access_key_id, secret_access_key, session_token,
        expiration.

    Raises:
        RuntimeError: If the HTTP request fails (non-2xx) or a network
            error occurs.
    """
    # Check cache first
    cache_key = _build_cache_key("domain_creds", user_email, domain_id)
    cached = _cache_get(cache_key)
    if cached is not None:
        logger.debug(
            "Step 3 (RedeemAccessToken) cache hit for user=%s domain=%s",
            user_email,
            domain_id,
        )
        return cached

    url = f"https://datazone.{region}.api.aws/sso/redeem-token"
    payload = {
        "domainId": domain_id,
        "accessToken": idc_access_token,
    }
    headers = {
        "Content-Type": "application/json",
    }

    try:
        response = requests.post(url, json=payload, headers=headers, timeout=30)
    except requests.exceptions.ConnectionError as exc:
        logger.error(
            "Step 3 (RedeemAccessToken) connection error — "
            "url=%s  domain_id=%s  error=%s",
            url,
            domain_id,
            exc,
        )
        raise RuntimeError(
            f"RedeemAccessToken failed: connection error to {url}. "
            f"Verify network connectivity to the DataZone endpoint "
            f"in region {region}."
        ) from exc
    except requests.exceptions.Timeout as exc:
        logger.error(
            "Step 3 (RedeemAccessToken) timeout — "
            "url=%s  domain_id=%s",
            url,
            domain_id,
        )
        raise RuntimeError(
            f"RedeemAccessToken failed: request timed out to {url}."
        ) from exc
    except requests.exceptions.RequestException as exc:
        logger.error(
            "Step 3 (RedeemAccessToken) request error — "
            "url=%s  domain_id=%s  error=%s",
            url,
            domain_id,
            exc,
        )
        raise RuntimeError(
            f"RedeemAccessToken failed: {exc} (url={url}, "
            f"domain_id={domain_id})"
        ) from exc

    if response.status_code != 200:
        # Truncate response body for logging to avoid leaking sensitive data
        body_preview = response.text[:500]
        logger.error(
            "Step 3 (RedeemAccessToken) HTTP error — "
            "status=%s  domain_id=%s  body=%s",
            response.status_code,
            domain_id,
            body_preview,
        )
        raise RuntimeError(
            f"RedeemAccessToken failed with HTTP {response.status_code} "
            f"for domain {domain_id}. Response: {body_preview}"
        )

    data = response.json()
    credentials = data["credentials"]

    logger.info(
        "Step 3 (RedeemAccessToken) succeeded — domain_id=%s  region=%s",
        domain_id,
        region,
    )

    result = {
        "access_key_id": credentials["accessKeyId"],
        "secret_access_key": credentials["secretAccessKey"],
        "session_token": credentials["sessionToken"],
        "expiration": credentials["expiration"],
    }

    # Cache with TTL based on expiration - 60s buffer
    ttl = _compute_expiration_ttl(result["expiration"])
    _cache_set(cache_key, result, ttl_seconds=ttl)

    return result


def _get_environment_credentials(
    domain_creds: dict[str, str],
    domain_id: str,
    environment_id: str,
    region: str,
    user_email: str,
) -> dict[str, str]:
    """Step 4: GetEnvironmentCredentials → final environment credentials.

    Uses the DomainExecutionRole credentials from Step 3 to call the
    DataZone GetEnvironmentCredentials API, obtaining the final
    environment-scoped credentials for Athena/Glue access.

    Results are cached with TTL based on the expiration field
    minus a 60-second buffer.

    Args:
        domain_creds: Dict with keys access_key_id, secret_access_key,
            session_token from Step 3 (RedeemAccessToken).
        domain_id: DataZone domain identifier.
        environment_id: DataZone environment identifier.
        region: AWS region for the DataZone domain.
        user_email: Current user's email (used for cache key).

    Returns:
        Dict with keys: aws_access_key_id, aws_secret_access_key,
        aws_session_token, expiration.

    Raises:
        RuntimeError: If the user lacks project membership
            (AccessDeniedException) or any other API error occurs.
    """
    # Check cache first
    cache_key = _build_cache_key("env_creds", user_email, domain_id, environment_id)
    cached = _cache_get(cache_key)
    if cached is not None:
        logger.debug(
            "Step 4 (GetEnvironmentCredentials) cache hit for user=%s "
            "domain=%s env=%s",
            user_email,
            domain_id,
            environment_id,
        )
        return cached

    # Create a boto3 session using the DomainExecutionRole credentials
    session = boto3.Session(
        aws_access_key_id=domain_creds["access_key_id"],
        aws_secret_access_key=domain_creds["secret_access_key"],
        aws_session_token=domain_creds["session_token"],
        region_name=region,
    )
    dz_client = session.client("datazone", region_name=region)

    try:
        response = dz_client.get_environment_credentials(
            domainIdentifier=domain_id,
            environmentIdentifier=environment_id,
        )
    except ClientError as exc:
        error_code = exc.response.get("Error", {}).get("Code", "Unknown")

        if error_code == "AccessDeniedException":
            logger.error(
                "Step 4 (GetEnvironmentCredentials) AccessDeniedException — "
                "domain_id=%s  environment_id=%s  "
                "hint: the user may not be a member of the DataZone project",
                domain_id,
                environment_id,
            )
            raise RuntimeError(
                f"GetEnvironmentCredentials failed with AccessDeniedException "
                f"for domain {domain_id}, environment {environment_id}. "
                f"The user may not be a member of the DataZone project "
                f"that owns this environment."
            ) from exc

        # Other ClientError
        logger.error(
            "Step 4 (GetEnvironmentCredentials) failed — "
            "error_code=%s  domain_id=%s  environment_id=%s",
            error_code,
            domain_id,
            environment_id,
        )
        raise RuntimeError(
            f"GetEnvironmentCredentials failed with error '{error_code}' "
            f"for domain {domain_id}, environment {environment_id}."
        ) from exc
    except BotoCoreError as exc:
        logger.error(
            "Step 4 (GetEnvironmentCredentials) BotoCoreError — "
            "domain_id=%s  environment_id=%s  error=%s",
            domain_id,
            environment_id,
            exc,
        )
        raise RuntimeError(
            f"GetEnvironmentCredentials failed for domain {domain_id}, "
            f"environment {environment_id}: {exc}"
        ) from exc

    # Extract credentials from the response
    # GetEnvironmentCredentials returns accessKeyId, secretAccessKey,
    # sessionToken, and expiration at the top level of the response dict.
    # Note: boto3 returns expiration as a datetime object — convert to
    # ISO 8601 string for cache serialization compatibility.
    access_key_id = response.get("accessKeyId", "")
    secret_access_key = response.get("secretAccessKey", "")
    session_token = response.get("sessionToken", "")
    raw_expiration = response.get("expiration", "")
    if hasattr(raw_expiration, "isoformat"):
        expiration = raw_expiration.isoformat()
    else:
        expiration = raw_expiration

    logger.info(
        "Step 4 (GetEnvironmentCredentials) succeeded — "
        "domain_id=%s  environment_id=%s",
        domain_id,
        environment_id,
    )

    result = {
        "aws_access_key_id": access_key_id,
        "aws_secret_access_key": secret_access_key,
        "aws_session_token": session_token,
        "expiration": expiration,
    }

    # Cache with TTL based on expiration - 60s buffer
    ttl = _compute_expiration_ttl(result["expiration"])
    _cache_set(cache_key, result, ttl_seconds=ttl)

    if ttl > 0:
        logger.info(
            "datazone_mutator: stored environment credentials in cache "
            "key=%s ttl=%ds",
            cache_key,
            ttl,
        )

    return result


# ---------------------------------------------------------------------------
# Credential scrubbing (Task 6.3)
# ---------------------------------------------------------------------------

# Patterns to redact in log messages
_SECRET_KEY_PATTERN = re.compile(
    r"((?:secret_access_key|SecretAccessKey|aws_secret_access_key)\s*[=:]\s*)"
    r"[^\s,}&\"']+",
    re.IGNORECASE,
)
_SESSION_TOKEN_PATTERN = re.compile(
    r"((?:session_token|SessionToken|aws_session_token)\s*[=:]\s*)"
    r"[^\s,}&\"']+",
    re.IGNORECASE,
)


def _scrub_credentials(msg: str) -> str:
    """Redact secret_access_key and session_token values from a string.

    Replaces the value portion of any key=value or key: value pair where
    the key matches secret_access_key or session_token patterns with '***'.

    Args:
        msg: The string to scrub.

    Returns:
        The scrubbed string with sensitive values replaced by '***'.
    """
    msg = _SECRET_KEY_PATTERN.sub(r"\g<1>***", msg)
    msg = _SESSION_TOKEN_PATTERN.sub(r"\g<1>***", msg)
    return msg


# ---------------------------------------------------------------------------
# URI rewriting (Task 6.1)
# ---------------------------------------------------------------------------

# Parameters to remove from the query string (DataZone-specific)
_DATAZONE_PARAMS_TO_REMOVE = {
    "CredentialsProvider",
    "DataZoneDomainId",
    "DataZoneEnvironmentId",
    "DataZoneDomainRegion",
    "IdentityCenterIssuerUrl",
}


def _build_datazone_url(
    uri: SqlaURL, creds: dict[str, str], dz_params: DataZoneConnectionParams
) -> SqlaURL:
    """Create a new SQLAlchemy URL with DataZone environment credentials.

    Builds a new URL preserving the original connection's drivername, host,
    port, and database, while injecting the environment credentials as
    username/password and adding the session token as a query parameter.

    Non-credential query parameters from the original URI are preserved
    (e.g., work_group, region_name, catalog_name). DataZone-specific
    parameters are removed from the query string.

    The original URI object is never mutated.

    Args:
        uri: The original SQLAlchemy URL.
        creds: Dict with keys: aws_access_key_id, aws_secret_access_key,
            aws_session_token.
        dz_params: Parsed DataZone connection parameters.

    Returns:
        A new SqlaURL with credentials injected.
    """
    # Preserve non-credential query params, remove DataZone-specific ones
    original_query = dict(getattr(uri, "query", {}))
    new_query: dict[str, str] = {
        k: v
        for k, v in original_query.items()
        if k not in _DATAZONE_PARAMS_TO_REMOVE
    }

    # Add the session token as a query parameter
    new_query["aws_session_token"] = creds["aws_session_token"]

    # Create a new URL with credentials as username/password
    new_url = SqlaURL.create(
        drivername=getattr(uri, "drivername", "awsathena+rest"),
        username=creds["aws_access_key_id"],
        password=creds["aws_secret_access_key"],
        host=getattr(uri, "host", None),
        port=getattr(uri, "port", None),
        database=getattr(uri, "database", None),
        query=new_query,
    )

    return new_url


# ---------------------------------------------------------------------------
# Mutator entry point (Task 1.3 + Task 6.2 / 6.4)
# ---------------------------------------------------------------------------


def datazone_connection_mutator(
    uri: SqlaURL,
    connect_args: dict[str, Any],
    effective_username: str | None,
    security_manager: Any,
    source: str | None,
) -> tuple[SqlaURL, dict[str, Any]]:
    """
    Superset DB_CONNECTION_MUTATOR hook for DataZone IDC credential flow.

    Detects DataZoneIdc connections by checking for
    CredentialsProvider=DataZoneIdc in the connection string query
    parameters. Non-matching connections are returned unchanged.

    For matching connections, resolves the current user and orchestrates
    the credential chain to inject per-user DataZone environment
    credentials into the SQLAlchemy URI.

    If any step raises an exception, the error is logged and the
    original URI is returned unchanged (graceful degradation).
    """
    # Guard: only process Athena connections
    drivername = getattr(uri, "drivername", "") or ""
    if not _ATHENA_DIALECT.search(drivername):
        return uri, connect_args

    # Guard: only process DataZoneIdc credential provider
    query_params: dict[str, Any] = dict(getattr(uri, "query", {}))
    credentials_provider = query_params.get("CredentialsProvider", "")
    if credentials_provider.lower() != "datazoneidc":
        return uri, connect_args

    # Parse DataZone-specific parameters from the connection string
    dz_params = parse_datazone_params(uri)
    if dz_params is None:
        logger.warning(
            "DataZoneIdc connection detected but required parameters are missing "
            "— returning URI unchanged"
        )
        return uri, connect_args

    # Resolve the current user
    user_email = _get_current_user_email()
    if not user_email:
        logger.warning(
            "datazone_mutator: no authenticated user — cannot obtain "
            "DataZone credentials, returning URI unchanged"
        )
        return uri, connect_args

    logger.info(
        "datazone_mutator: detected DataZoneIdc connection for user=%s "
        "domain=%s env=%s region=%s",
        user_email,
        dz_params.domain_id,
        dz_params.environment_id,
        dz_params.domain_region,
    )

    # --- Top-level try/except (Task 6.4) ---
    # Catches all exceptions from the credential chain and returns the
    # original URI unchanged so Superset never receives an unhandled error.
    try:
        # Top-level cache check - before Cognito token resolution
        final_cache_key = _build_cache_key(
            "env_creds", user_email, dz_params.domain_id, dz_params.environment_id
        )
        cached_final = _cache_get(final_cache_key)
        if cached_final is not None:
            if not _is_credential_expired(cached_final, _get_ttl_buffer()):
                # Cache hit with valid credentials - skip entire chain
                remaining_ttl = _compute_expiration_ttl(
                    cached_final.get("expiration"), _get_ttl_buffer()
                )
                logger.info(
                    "datazone_mutator: top-level cache HIT for user=%s "
                    "domain=%s env=%s remaining_ttl=%ds — skipping chain",
                    user_email,
                    dz_params.domain_id,
                    dz_params.environment_id,
                    remaining_ttl,
                )
                new_url = _build_datazone_url(uri, cached_final, dz_params)
                logger.info(
                    "datazone_mutator: rewrote URI for user=%s — %s",
                    user_email,
                    _scrub_credentials(str(new_url)),
                )
                return new_url, connect_args
            else:
                logger.info(
                    "datazone_mutator: top-level cache EXPIRED for user=%s "
                    "domain=%s env=%s — executing full chain",
                    user_email,
                    dz_params.domain_id,
                    dz_params.environment_id,
                )
        else:
            logger.info(
                "datazone_mutator: top-level cache MISS for user=%s "
                "domain=%s env=%s — executing full chain",
                user_email,
                dz_params.domain_id,
                dz_params.environment_id,
            )

        # Step 0: Get Cognito ID token
        cognito_id_token = _get_cognito_id_token(user_email)
        if not cognito_id_token:
            logger.warning(
                "datazone_mutator: no Cognito token for user=%s "
                "- cannot proceed with DataZone flow, returning URI unchanged",
                user_email,
            )
            return uri, connect_args

        # Validate required environment variables
        if not OIDC_ROLE_ARN:
            logger.info(
                "datazone_mutator: OIDC_ROLE_ARN environment variable is not set "
                "- using environment role"
            )

        if not IDC_APPLICATION_ARN:
            logger.error(
                "datazone_mutator: IDC_APPLICATION_ARN environment variable is not set "
                "- cannot execute token chain"
            )
            return uri, connect_args

        # Execute the token exchange chain (Steps 1-4) with retry-once
        # on authentication failure.
        try:
            # Step 1: AssumeRoleWithWebIdentity → intermediary IAM credentials
            intermediary_creds = _assume_role_with_web_identity(
                cognito_id_token, OIDC_ROLE_ARN, user_email
            )

            # Step 2: CreateTokenWithIAM → IDC access token
            idc_token_data = _create_token_with_iam(
                cognito_id_token, intermediary_creds, IDC_APPLICATION_ARN, user_email
            )
            idc_access_token = idc_token_data["access_token"]

            # Step 3: RedeemAccessToken → DomainExecutionRole credentials
            domain_creds = _redeem_access_token(
                idc_access_token,
                dz_params.domain_id,
                dz_params.domain_region,
                user_email,
            )

            # Step 4: GetEnvironmentCredentials → final environment credentials
            env_creds = _get_environment_credentials(
                domain_creds,
                dz_params.domain_id,
                dz_params.environment_id,
                dz_params.domain_region,
                user_email,
            )
        except RuntimeError as chain_exc:
            # Check if this is an auth failure that warrants cache
            # invalidation and retry
            error_msg = str(chain_exc)
            is_auth_failure = any(
                err_type in error_msg
                for err_type in (
                    "ExpiredTokenException",
                    "InvalidCredentialsException",
                )
            )
            if not is_auth_failure:
                raise

            logger.warning(
                "datazone_mutator: auth failure detected — invalidating "
                "cache key=%s error=%s — retrying chain once",
                final_cache_key,
                type(chain_exc).__name__,
            )
            _invalidate_cache_entry(final_cache_key)

            # Retry the full chain once
            try:
                intermediary_creds = _assume_role_with_web_identity(
                    cognito_id_token, OIDC_ROLE_ARN, user_email
                )
                idc_token_data = _create_token_with_iam(
                    cognito_id_token,
                    intermediary_creds,
                    IDC_APPLICATION_ARN,
                    user_email,
                )
                idc_access_token = idc_token_data["access_token"]
                domain_creds = _redeem_access_token(
                    idc_access_token,
                    dz_params.domain_id,
                    dz_params.domain_region,
                    user_email,
                )
                env_creds = _get_environment_credentials(
                    domain_creds,
                    dz_params.domain_id,
                    dz_params.environment_id,
                    dz_params.domain_region,
                    user_email,
                )
            except Exception:  # noqa: BLE001
                logger.warning(
                    "datazone_mutator: retry also failed for user=%s "
                    "— returning original URI unchanged",
                    user_email,
                )
                return uri, connect_args

        # Build the new URL with the environment credentials
        new_url = _build_datazone_url(uri, env_creds, dz_params)

        logger.info(
            "datazone_mutator: rewrote URI for user=%s — %s",
            user_email,
            _scrub_credentials(str(new_url)),
        )

        return new_url, connect_args

    except Exception:  # noqa: BLE001
        logger.exception(
            "datazone_mutator: credential chain failed for user=%s "
            "domain=%s env=%s — returning original URI unchanged",
            user_email,
            dz_params.domain_id,
            dz_params.environment_id,
        )
        return uri, connect_args
