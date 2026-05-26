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

# -----------------------------------------------------------------------
# AWS Cognito User Pool (OIDC) Authentication Configuration
#
# Required environment variables (set in docker/.env-local):
#
#   COGNITO_CLIENT_ID       - App client ID from the Cognito User Pool
#   COGNITO_CLIENT_SECRET   - App client secret from the Cognito User Pool
#   SUPERSET_PUBLIC_URL     - Public URL of this Superset instance, e.g.:
#                             http://localhost:8088
#
# Cognito setup steps:
#   1. Go to Cognito > User Pools > <your pool> > App clients
#   2. Create or select an app client with a client secret
#   3. Under "Hosted UI", add allowed callback URL:
#      <SUPERSET_PUBLIC_URL>/oauth-authorized/cognito
#   4. Enable scopes: openid, email, profile
#   5. Copy the client ID and secret here
#
# Note: The Athena JDBC driver handles Identity Center authentication
#       natively via the DataZoneIdc credentials provider. The connection
#       mutator only injects the required JDBC properties.
# -----------------------------------------------------------------------

import logging
import os
import re
from typing import Any

from flask_appbuilder.security.manager import AUTH_OAUTH
from redis import Redis
from sqlalchemy.engine.url import URL as SqlaURL

from athena_rest_connection_mutator import athena_rest_connection_mutator
from custom_sso_security_manager import CustomSsoSecurityManager
from datazone_connection_mutator import datazone_connection_mutator

# ---------------------------------------------------------------------------
# Logging: suppress noisy third-party loggers, ensure mutator logs are visible
# ---------------------------------------------------------------------------
logging.getLogger("watchdog").setLevel(logging.WARNING)
logging.getLogger("watchdog.observers.inotify_buffer").setLevel(logging.WARNING)
logging.getLogger("athena_connection_mutator").setLevel(logging.DEBUG)
logging.getLogger("datazone_connection_mutator").setLevel(logging.DEBUG)
logging.getLogger("pyathenajdbc.cursor").setLevel(logging.DEBUG)
logging.getLogger("pyathenajdbc.sqlalchemy_athena").setLevel(logging.DEBUG)

LOG_LEVEL = "INFO"

CUSTOM_SECURITY_MANAGER = CustomSsoSecurityManager

# ---------------------------------------------------------------------------
# Server-side sessions (Redis)
# The Cognito ID token stored in the session exceeds the 4 KB browser cookie
# limit. Storing sessions in Redis keeps the cookie small (just a session ID).
# ---------------------------------------------------------------------------
SESSION_TYPE = "redis"
SESSION_REDIS = Redis(
    host=os.getenv("REDIS_HOST", "redis"),
    port=int(os.getenv("REDIS_PORT", "6379")),
    db=0,
)
SESSION_PERMANENT = True
SESSION_SERVER_SIDE = True

AUTH_TYPE = AUTH_OAUTH

# Allow users to self-register on first login
AUTH_USER_REGISTRATION = True

# Default role assigned to new users — change to "Alpha" or "Admin" as needed
AUTH_USER_REGISTRATION_ROLE = os.getenv("COGNITO_DEFAULT_ROLE", "Gamma")

# Map role_keys returned by oauth_user_info to Superset roles on every login.
# The key is the value from role_keys; the value is the Superset role name.
AUTH_ROLES_MAPPING = {
    "Admin": ["Admin"],
    "Gamma": ["Gamma"],
}

# Re-sync roles on every login, not just on first registration
AUTH_ROLES_SYNC_AT_LOGIN = True

_cognito_issuer = "https://cognito-idp.eu-central-1.amazonaws.com/eu-central-1_K8UfZDRlf"

# Must exactly match one of the allowed callback URLs in the Cognito app client.
# Set SUPERSET_PUBLIC_URL in docker/.env-local to your externally reachable URL.
_public_url = os.getenv("SUPERSET_PUBLIC_URL", "http://localhost").rstrip("/")
_redirect_uri = f"{_public_url}/oauth-authorized/cognito"

# ---------------------------------------------------------------------------
# DB_CONNECTION_MUTATOR — Composite Athena Connection Mutator
#
# This composite mutator routes Athena connections to the appropriate
# credential flow based on the CredentialsProvider query parameter:
#
#   • CredentialsProvider=DataZoneIdc → DataZone IDC credential chain
#     (Cognito → STS → SSO-OIDC → DataZone → environment credentials)
#
#   • All other Athena connections → TIP credential flow
#     (Cognito → STS AssumeRoleWithWebIdentity → Lake Formation)
#
#   • Non-Athena connections → returned unchanged
#
# To use only the DataZone mutator:
#   DB_CONNECTION_MUTATOR = datazone_connection_mutator
#
# To use only the TIP mutator:
#   DB_CONNECTION_MUTATOR = athena_rest_connection_mutator
#
# To use both (default — routes automatically):
#   DB_CONNECTION_MUTATOR = composite_connection_mutator
#
# Required environment variables for DataZone flow (docker/.env-local):
#   OIDC_ROLE_ARN              - IAM role trusted by Cognito for web identity
#   IDC_APPLICATION_ARN        - Identity Center application ARN
#   DATAZONE_DOMAIN_ID         - DataZone domain identifier
#   DATAZONE_ENVIRONMENT_ID    - DataZone environment identifier
#   AWS_REGION                 - AWS region (default: eu-central-1)
#
# Required environment variables for TIP flow (docker/.env-local):
#   USER_ENHANCED_ROLE_ARN     - IAM role for Lake Formation access
# ---------------------------------------------------------------------------

_ATHENA_DIALECT_RE = re.compile(r"awsathena", re.IGNORECASE)


def composite_connection_mutator(
    uri: SqlaURL,
    connect_args: dict[str, Any],
    effective_username: str | None,
    security_manager: Any,
    source: str | None,
) -> tuple[SqlaURL, dict[str, Any]]:
    """Composite Superset DB_CONNECTION_MUTATOR that routes to the correct flow.

    Routing logic:
      1. Non-Athena connections are returned unchanged immediately.
      2. Athena connections with ``CredentialsProvider=DataZoneIdc`` in the
         query parameters are routed to the DataZone IDC credential chain.
      3. All other Athena connections are routed to the TIP credential flow
         (Lake Formation row/column-level security).
    """
    # Non-Athena connections pass through unchanged
    drivername = getattr(uri, "drivername", "") or ""
    if not _ATHENA_DIALECT_RE.search(drivername):
        return uri, connect_args

    # Check for DataZoneIdc credential provider in query params
    query_params: dict[str, Any] = dict(getattr(uri, "query", {}))
    credentials_provider = query_params.get("CredentialsProvider", "")
    if credentials_provider.lower() == "datazoneidc":
        return datazone_connection_mutator(
            uri, connect_args, effective_username, security_manager, source
        )

    return uri


DB_CONNECTION_MUTATOR = composite_connection_mutator

OAUTH_PROVIDERS = [
    {
        "name": "cognito",
        "token_key": "access_token",
        "icon": "fa-amazon",
        "remote_app": {
            "client_id": os.environ["COGNITO_CLIENT_ID"],
            "client_secret": os.environ["COGNITO_CLIENT_SECRET"],
            "client_kwargs": {
                "scope": "openid email",
            },
            "allowUnsafeReuseRefreshToken": "true",
            "redirect_uri": _redirect_uri,
            # Cognito exposes a standard OIDC discovery endpoint
            "server_metadata_url": f"{_cognito_issuer}/.well-known/openid-configuration",
        },
    }
]