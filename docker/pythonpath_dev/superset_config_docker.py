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

from flask_appbuilder.security.manager import AUTH_OAUTH
from redis import Redis

from athena_connection_mutator import athena_db_connection_mutator
from custom_sso_security_manager import CognitoSecurityManager

# ---------------------------------------------------------------------------
# Logging: suppress noisy third-party loggers, ensure mutator logs are visible
# ---------------------------------------------------------------------------
logging.getLogger("watchdog").setLevel(logging.WARNING)
logging.getLogger("watchdog.observers.inotify_buffer").setLevel(logging.WARNING)
logging.getLogger("athena_connection_mutator").setLevel(logging.DEBUG)
logging.getLogger("pyathenajdbc.cursor").setLevel(logging.DEBUG)
logging.getLogger("pyathenajdbc.sqlalchemy_athena").setLevel(logging.DEBUG)

LOG_LEVEL = "INFO"

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
# Per-user Athena access via the Athena JDBC driver's built-in DataZoneIdc
# credentials provider.  The driver handles the full Identity Center SSO
# flow natively — no manual token exchange or STS calls needed.
#
# Required environment variables (set in docker/.env-local):
#   DATAZONE_DOMAIN_ID         - DataZone domain identifier
#   DATAZONE_ENVIRONMENT_ID    - DataZone environment identifier
#   DATAZONE_DOMAIN_REGION     - AWS region of the DataZone domain
#   IDENTITY_CENTER_ISSUER_URL - IAM Identity Center issuer URL
#   AWS_REGION                 - AWS region (default: eu-central-1)
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
# Monkey-patch PyAthenaJDBC dialect to use SHOW/DESCRIBE instead of
# information_schema queries.  information_schema does not exist in
# S3 Table Catalogs, so the default queries fail with INTERNAL_ERROR
# or CATALOG_NOT_FOUND.
# ---------------------------------------------------------------------------
_patch_logger = logging.getLogger("pyathenajdbc.sqlalchemy_athena.patch")


def _patched_get_schema_names(self, connection, **kw):
    query = "SHOW DATABASES"
    _patch_logger.info("get_schema_names: %s", query)
    try:
        result = [row[0] for row in connection.execute(query).fetchall()]
        _patch_logger.info("get_schema_names returned %d schemas: %s", len(result), result)
        return result
    except Exception as e:
        _patch_logger.warning(
            "get_schema_names FAILED (%s), falling back to SHOW NAMESPACES: %s",
            query, e,
        )
    # Fallback: try SHOW NAMESPACES (S3 Table Catalog terminology)
    try:
        query2 = "SHOW NAMESPACES"
        result = [row[0] for row in connection.execute(query2).fetchall()]
        _patch_logger.info("get_schema_names (SHOW NAMESPACES) returned %d: %s", len(result), result)
        return result
    except Exception as e2:
        _patch_logger.warning("SHOW NAMESPACES also failed: %s", e2)
    # Last resort: return the schema from the connection URL
    try:
        raw_conn = self._raw_connection(connection)
        schema = getattr(raw_conn, "schema_name", None)
        if schema:
            _patch_logger.info("get_schema_names fallback to connection schema: %s", schema)
            return [schema]
    except Exception:
        pass
    _patch_logger.error("get_schema_names: all methods failed, returning empty list")
    return []


def _patched_get_table_names(self, connection, schema=None, **kw):
    raw_connection = self._raw_connection(connection)
    schema = schema if schema else raw_connection.schema_name
    query = 'SHOW TABLES IN "{0}"'.format(schema)
    _patch_logger.info("get_table_names (schema=%s): %s", schema, query)
    try:
        result = [row[0] for row in connection.execute(query).fetchall()]
        _patch_logger.info("get_table_names returned %d tables: %s", len(result), result)
        return result
    except Exception as e:
        _patch_logger.error("get_table_names FAILED (schema=%s): %s", schema, e)
        raise


def _patched_get_columns(self, connection, table_name, schema=None, **kw):
    raw_connection = self._raw_connection(connection)
    schema = schema if schema else raw_connection.schema_name
    query = 'DESCRIBE "{0}"."{1}"'.format(schema, table_name)
    _patch_logger.info("get_columns: %s", query)
    try:
        from sqlalchemy import types as sa_types

        columns = []
        for row in connection.execute(query).fetchall():
            col_name = row[0]
            col_type = row[1] if len(row) > 1 else "string"
            if not col_name or col_name.startswith("#") or col_name.strip() == "":
                continue
            col_name = col_name.strip()
            col_type = col_type.strip() if col_type else "string"
            columns.append(
                {
                    "name": col_name,
                    "type": sa_types.NullType(),
                    "nullable": True,
                    "default": None,
                    "ordinal_position": len(columns) + 1,
                    "comment": row[2].strip() if len(row) > 2 and row[2] else None,
                }
            )
        _patch_logger.info(
            "get_columns returned %d columns for %s.%s",
            len(columns), schema, table_name,
        )
        return columns
    except Exception as e:
        _patch_logger.error("get_columns FAILED (%s.%s): %s", schema, table_name, e)
        raise


try:
    from pyathenajdbc.sqlalchemy_athena import AthenaDialect

    # Also patch create_connect_args to log final JDBC properties
    _original_create_connect_args = AthenaDialect.create_connect_args

    def _patched_create_connect_args(self, url):
        args, opts = _original_create_connect_args(self, url)
        safe_opts = {
            k: ("***" if "token" in k.lower() or "secret" in k.lower()
                 or "password" in k.lower() else v)
            for k, v in opts.items()
        }
        _patch_logger.info("JDBC create_connect_args opts: %s", safe_opts)
        return args, opts

    AthenaDialect.get_schema_names = _patched_get_schema_names
    AthenaDialect.get_table_names = _patched_get_table_names
    AthenaDialect.get_columns = _patched_get_columns
    AthenaDialect.create_connect_args = _patched_create_connect_args
    _patch_logger.info("Patched AthenaDialect: information_schema -> SHOW/DESCRIBE")
except ImportError:
    _patch_logger.warning("PyAthenaJDBC not installed — dialect patch skipped")
