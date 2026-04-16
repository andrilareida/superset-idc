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
DB_CONNECTION_MUTATOR for Athena JDBC v3 with JWT_TIP authentication.

The Athena JDBC v3 driver (≥ 3.6.0) has a built-in ``JWT_TIP``
credentials provider that handles the full Trusted Identity Propagation
flow: it exchanges a JWT token for Identity Center credentials, then
assumes a role via STS — all inside the driver.

This mutator:
  1. Patches PyAthenaJDBC to load the Athena JDBC v3 JAR instead of
     the bundled Simba v2 driver.
  2. Copies ``CredentialsProvider`` → ``AwsCredentialsProviderClass``
     to override PyAthenaJDBC's hardcoded default.
  3. Injects the per-user Cognito ID token as ``JwtWebIdentityToken``
     from the Flask session.

The connection string configured in Superset should contain all static
JWT_TIP parameters.  Example::

    awsathena+jdbc://athena.eu-central-1.amazonaws.com:443/?
      CredentialsProvider=JWT_TIP&
      ApplicationRoleArn=arn:aws:iam::123456789012:role/my-role&
      WorkGroupArn=arn:aws:athena:eu-central-1:123456789012:workgroup/my-wg&
      JwtRoleSessionName=superset&
      Region=eu-central-1&
      ...

The mutator adds ``JwtWebIdentityToken`` at query time from the
logged-in user's Cognito session.
"""

import logging
import os
import re
from typing import Any

import flask
from flask_login import current_user
from sqlalchemy.engine.url import URL as SqlaURL

logger = logging.getLogger(__name__)

_ATHENA_DIALECT = re.compile(r"awsathena", re.IGNORECASE)
_V3_JAR = os.environ.get(
    "ATHENA_JDBC_DRIVER_PATH",
    "/app/jdbc-drivers/athena-jdbc-3.7.0-with-dependencies.jar",
)


def _patch_pyathenajdbc_for_v3() -> None:
    """Patch PyAthenaJDBC constants so it loads the Athena JDBC v3 driver."""
    import pyathenajdbc

    if pyathenajdbc.ATHENA_DRIVER_CLASS_NAME != "com.amazon.athena.jdbc.AthenaDriver":
        pyathenajdbc.ATHENA_DRIVER_CLASS_NAME = "com.amazon.athena.jdbc.AthenaDriver"
        pyathenajdbc.ATHENA_CONNECTION_STRING = "jdbc:athena://AwsRegion={region};"
        logger.info(
            "athena_mutator: patched PyAthenaJDBC for v3 driver "
            "(class=%s, url=%s)",
            pyathenajdbc.ATHENA_DRIVER_CLASS_NAME,
            pyathenajdbc.ATHENA_CONNECTION_STRING,
        )


def _store_cognito_tokens_in_redis(user_email: str) -> None:
    """Replicate Cognito tokens from the Flask session to Redis."""
    try:
        id_token = flask.session.get("cognito_id_token")
        refresh_token = flask.session.get("cognito_refresh_token")
        if id_token:
            _store_cognito_tokens_in_redis_direct(
                user_email, id_token, refresh_token
            )
    except RuntimeError:
        pass


def _store_cognito_tokens_in_redis_direct(
    user_email: str, id_token: str, refresh_token: str | None = None
) -> None:
    """Store Cognito tokens directly to Redis."""
    try:
        import json

        from redis import Redis

        redis_host = os.environ.get("REDIS_HOST", "redis")
        redis_port = int(os.environ.get("REDIS_PORT", "6379"))
        r = Redis(host=redis_host, port=redis_port, db=0)
        key = f"cognito_tokens:{user_email}"
        payload = {"id_token": id_token}
        if refresh_token:
            payload["refresh_token"] = refresh_token
        r.setex(key, 86400, json.dumps(payload))
        logger.info("athena_mutator: stored tokens in Redis for %s", user_email)
    except Exception:  # noqa: BLE001
        logger.warning(
            "athena_mutator: failed to store tokens in Redis for %s",
            user_email,
            exc_info=True,
        )


def _get_cognito_id_token(user_email: str | None = None) -> str | None:
    """Read the Cognito ID token from the Flask session or Redis.

    In the web request context, reads from the Flask session.
    In the Celery worker / SQL Lab context (no session), falls back to Redis.
    Refreshes the token if expired.
    """
    token = None

    # 1. Try Flask session
    try:
        token = flask.session.get("cognito_id_token")
    except RuntimeError:
        pass

    # 2. Fall back to Redis (worker / SQL Lab context)
    if not token and user_email:
        token = _get_token_from_redis(user_email)

    if not token:
        return None

    # 3. Check expiry and refresh if needed
    try:
        import time

        import jwt as pyjwt

        claims = pyjwt.decode(
            token, options={"verify_signature": False}, algorithms=["RS256"]
        )
        exp = claims.get("exp", 0)
        if time.time() >= (exp - 60):
            logger.info("athena_mutator: Cognito ID token expired — refreshing")
            refreshed = _refresh_cognito_id_token(user_email)
            if refreshed:
                token = refreshed
    except Exception:  # noqa: BLE001
        logger.warning(
            "athena_mutator: could not check token expiry — using as-is"
        )

    return token


def _get_token_from_redis(user_email: str) -> str | None:
    """Read the Cognito ID token from Redis."""
    try:
        import json

        from redis import Redis

        redis_host = os.environ.get("REDIS_HOST", "redis")
        redis_port = int(os.environ.get("REDIS_PORT", "6379"))
        r = Redis(host=redis_host, port=redis_port, db=0)
        raw = r.get(f"cognito_tokens:{user_email}")
        if raw:
            data = json.loads(raw)
            token = data.get("id_token")
            if token:
                logger.info(
                    "athena_mutator: retrieved Cognito token from Redis for %s",
                    user_email,
                )
                return token
    except Exception:  # noqa: BLE001
        logger.warning("athena_mutator: failed to read token from Redis")
    return None


def _refresh_cognito_id_token(user_email: str | None = None) -> str | None:
    """Refresh the Cognito ID token using the stored refresh token."""
    refresh_token = None

    # Try Flask session first
    try:
        refresh_token = flask.session.get("cognito_refresh_token")
    except RuntimeError:
        pass

    # Fall back to Redis
    if not refresh_token and user_email:
        try:
            import json

            from redis import Redis

            r = Redis(
                host=os.environ.get("REDIS_HOST", "redis"),
                port=int(os.environ.get("REDIS_PORT", "6379")),
                db=0,
            )
            raw = r.get(f"cognito_tokens:{user_email}")
            if raw:
                data = json.loads(raw)
                refresh_token = data.get("refresh_token")
        except Exception:  # noqa: BLE001
            pass

    if not refresh_token:
        logger.info("athena_mutator: no refresh token — cannot refresh")
        return None

    client_id = os.environ.get("COGNITO_CLIENT_ID", "")
    client_secret = os.environ.get("COGNITO_CLIENT_SECRET", "")
    region = os.environ.get("AWS_REGION", "eu-central-1")

    if not client_id:
        logger.warning("athena_mutator: COGNITO_CLIENT_ID not set")
        return None

    try:
        import boto3

        cognito = boto3.client("cognito-idp", region_name=region)
        auth_params: dict[str, str] = {"REFRESH_TOKEN": refresh_token}

        if client_secret:
            import base64
            import hashlib
            import hmac

            username = flask.session.get("cognito_username", "")
            if username:
                msg = username + client_id
                secret_hash = base64.b64encode(
                    hmac.new(
                        client_secret.encode(), msg.encode(), hashlib.sha256
                    ).digest()
                ).decode()
                auth_params["SECRET_HASH"] = secret_hash

        response = cognito.initiate_auth(
            ClientId=client_id,
            AuthFlow="REFRESH_TOKEN_AUTH",
            AuthParameters=auth_params,
        )
        new_token = response.get("AuthenticationResult", {}).get("IdToken")
        if new_token:
            # Update Flask session if available
            try:
                flask.session["cognito_id_token"] = new_token
            except RuntimeError:
                pass
            # Update Redis
            if user_email:
                _store_cognito_tokens_in_redis_direct(
                    user_email, new_token, refresh_token
                )
            logger.info("athena_mutator: refreshed Cognito ID token")
            return new_token
    except Exception:  # noqa: BLE001
        logger.warning("athena_mutator: token refresh failed", exc_info=True)

    return None


def _get_current_user_email() -> str | None:
    """Resolve the current user's email for the session name."""
    try:
        if current_user and not current_user.is_anonymous:
            return current_user.email or None
    except RuntimeError:
        pass
    try:
        user = getattr(flask.g, "user", None)
        if user and not user.is_anonymous:
            return user.email or None
    except RuntimeError:
        pass
    return None


def athena_db_connection_mutator(
    uri: Any,
    connect_args: dict[str, Any],
    effective_username: str | None,
    security_manager: Any,
    source: str | None,
) -> tuple[Any, dict[str, Any]]:
    """
    Superset DB_CONNECTION_MUTATOR hook.

    For Athena JDBC connections with ``CredentialsProvider=JWT_TIP``,
    injects the per-user Cognito ID token and patches PyAthenaJDBC to
    use the Athena JDBC v3 driver.

    Non-Athena, non-JDBC, and connections without a CredentialsProvider
    pass through unchanged.
    """
    uri_str = str(uri)
    if not _ATHENA_DIALECT.search(uri_str):
        return uri, connect_args

    drivername = getattr(uri, "drivername", "awsathena+rest")
    if "jdbc" not in drivername.lower():
        return uri, connect_args

    original_query = dict(getattr(uri, "query", {}))
    creds_provider = original_query.get("CredentialsProvider", "")

    if not creds_provider:
        logger.info("athena_mutator: no CredentialsProvider — passing through")
        return uri, connect_args

    logger.info("athena_mutator: CredentialsProvider=%s", creds_provider)

    # --- Build new query params ---
    query_params = dict(original_query)

    # 1. Copy CredentialsProvider → AwsCredentialsProviderClass to override
    #    PyAthenaJDBC's hardcoded DefaultAWSCredentialsProviderChain.
    query_params["AwsCredentialsProviderClass"] = creds_provider

    # 2. Point PyAthenaJDBC at the v3 JAR and patch its constants.
    if "driver_path" not in query_params and os.path.isfile(_V3_JAR):
        query_params["driver_path"] = _V3_JAR
        _patch_pyathenajdbc_for_v3()
    elif not os.path.isfile(_V3_JAR):
        logger.error("athena_mutator: v3 JAR not found at %s", _V3_JAR)
        return uri, connect_args

    # 3. For JWT_TIP: inject the per-user Cognito ID token.
    if creds_provider.upper() == "JWT_TIP":
        user_email = _get_current_user_email()

        # Store tokens to Redis on every web request so SQL Lab can use them
        if user_email:
            _store_cognito_tokens_in_redis(user_email)

        id_token = _get_cognito_id_token(user_email=user_email)
        if not id_token:
            logger.warning(
                "athena_mutator: no Cognito ID token available — "
                "JWT_TIP auth will fail"
            )
            return uri, connect_args

        query_params["JwtWebIdentityToken"] = id_token

        # Set session name to user email if not already configured
        if "JwtRoleSessionName" not in query_params:
            if user_email:
                safe_name = re.sub(r"[^a-zA-Z0-9+=,.@-]", "-", user_email)[:64]
                query_params["JwtRoleSessionName"] = safe_name

        logger.info(
            "athena_mutator: injected JwtWebIdentityToken for user %s",
            user_email or effective_username or "unknown",
        )

    new_url = SqlaURL.create(
        drivername=drivername,
        username=getattr(uri, "username", None),
        password=getattr(uri, "password", None),
        host=getattr(uri, "host", None),
        database=getattr(uri, "database", None),
        port=getattr(uri, "port", None),
        query=query_params,
    )

    logger.info(
        "athena_mutator: rewrote URI — CredentialsProvider=%s  driver=v3",
        creds_provider,
    )

    # Log all JDBC params (except tokens) for debugging
    safe_params = {
        k: ("***" if "token" in k.lower() or "secret" in k.lower() or "password" in k.lower() else v)
        for k, v in query_params.items()
    }
    logger.info("athena_mutator: JDBC params: %s", safe_params)
    logger.info("athena_mutator: database (Schema): %s", getattr(new_url, "database", None))

    return new_url, connect_args
