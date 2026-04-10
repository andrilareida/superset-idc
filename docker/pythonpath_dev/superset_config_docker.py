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
# Note: AWS Identity Center is used internally by the Athena DB_CONNECTION_MUTATOR
#       for per-user STS AssumeRoleWithWebIdentity using the user's OIDC id_token.
# -----------------------------------------------------------------------

import os

from flask_appbuilder.security.manager import AUTH_OAUTH
from redis import Redis

from athena_connection_mutator import athena_db_connection_mutator
from custom_sso_security_manager import CognitoSecurityManager

CUSTOM_SECURITY_MANAGER = CognitoSecurityManager

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
# Per-user Athena access via SageMaker Unified Studio identity propagation.
# AWS Identity Center credentials are used only here (STS AssumeRole), not
# for Superset login.
#
# Required environment variables (set in docker/.env-local):
#   ATHENA_EXECUTION_ROLE_ARN  - SageMaker Unified Studio project execution role
#   ATHENA_S3_STAGING_DIR      - S3 path for Athena query results
#   AWS_REGION                 - AWS region (default: eu-central-1)
#   IDC_APPLICATION_ARN        - Identity Center application ARN used in the
#                                CreateTokenWithIAM call (TIP flow)
# ---------------------------------------------------------------------------
DB_CONNECTION_MUTATOR = athena_db_connection_mutator

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

# ---------------------------------------------------------------------------
# Debug: log Athena API requests and responses
# ---------------------------------------------------------------------------
import logging as _logging

# _logging.getLogger("botocore.endpoint").setLevel(_logging.DEBUG)
# _logging.getLogger("botocore.parsers").setLevel(_logging.DEBUG)
