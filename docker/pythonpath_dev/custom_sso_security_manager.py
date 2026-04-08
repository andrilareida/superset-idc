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

import logging

import jwt
from flask import session as flask_session
from superset.security import SupersetSecurityManager

logger = logging.getLogger(__name__)

COGNITO_GROUP_ROLE_MAP = {
    "superset_admins": "Admin",
}
_DEFAULT_ROLE = "Gamma"


class CognitoSecurityManager(SupersetSecurityManager):
    """
    Maps Cognito User Pool OIDC claims to Superset user attributes and
    maps Cognito group membership to Superset roles.
    """

    def oauth_user_info(
        self, provider: str, response: dict | None = None
    ) -> dict[str, str]:
        if provider != "cognito":
            return super().oauth_user_info(provider, response)

        me = self.appbuilder.sm.oauth_remotes[provider].userinfo()
        logger.debug("Cognito user info: %s", me)

        first_name = me.get("given_name", "")
        last_name = me.get("family_name", "")

        if not first_name and not last_name:
            parts = me.get("name", "").split(" ", 1)
            first_name = parts[0]
            last_name = parts[1] if len(parts) > 1 else ""

        username = me.get("email", me.get("sub", ""))

        # cognito:groups is in the ID token, not always in the userinfo endpoint.
        # Decode it from the raw id_token in the response (no sig verification
        # needed here — Authlib already validated the token).
        groups: list[str] = me.get("cognito:groups", [])
        if not groups and response:
            try:
                id_token = response.get("id_token", "")
                if id_token:
                    claims = jwt.decode(
                        id_token,
                        options={"verify_signature": False},
                        algorithms=["RS256"],
                    )
                    groups = claims.get("cognito:groups", [])
            except Exception:  # noqa: BLE001
                logger.warning("Could not decode id_token to extract Cognito groups")

        role = _DEFAULT_ROLE
        for group in groups:
            if group in COGNITO_GROUP_ROLE_MAP:
                role = COGNITO_GROUP_ROLE_MAP[group]
                break

        logger.debug("Cognito user %s → groups %s → role %s", username, groups, role)

        # Store the raw ID token for later use by the Connection_Mutator (TIP flow)
        if response and response.get("id_token"):
            flask_session["cognito_id_token"] = response["id_token"]
        # Store the refresh token so the mutator can refresh expired ID tokens
        if response and response.get("refresh_token"):
            flask_session["cognito_refresh_token"] = response["refresh_token"]
        # Store the Cognito username for SECRET_HASH computation during
        # token refresh. When the User Pool uses email as a sign-in alias,
        # Cognito expects the *sub* (UUID) in the SECRET_HASH — this is the
        # internal username regardless of alias configuration.
        # We store both so the mutator can fall back if needed.
        flask_session["cognito_username"] = me.get("sub", username)
        flask_session["cognito_email"] = me.get("email", username)

        return {
            "username": username,
            "email": me.get("email", ""),
            "first_name": first_name,
            "last_name": last_name,
            "id": me.get("sub", ""),
            "name": me.get("name", f"{first_name} {last_name}".strip()),
            "role_keys": [role],
        }
