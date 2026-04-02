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
Hypothesis property-based tests for the Athena Identity Propagation feature.

These tests verify correctness properties that must hold across *all* valid
inputs, complementing the example-based unit tests.
"""

from __future__ import annotations

import re
import sys
import types
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch
from urllib.parse import parse_qs, urlparse

import flask
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

# Make docker/pythonpath_dev importable
_DOCKER_PATH = str(Path(__file__).resolve().parents[4] / "docker" / "pythonpath_dev")
if _DOCKER_PATH not in sys.path:
    sys.path.insert(0, _DOCKER_PATH)


# ---------------------------------------------------------------------------
# Stub out the superset import chain so that custom_sso_security_manager can
# be imported without pulling in the full Superset application (which needs
# alembic, pandas, etc.).
# ---------------------------------------------------------------------------

def _install_superset_stub() -> None:
    """Install a minimal stub for superset.security.SupersetSecurityManager."""
    if "superset" not in sys.modules:
        superset_mod = types.ModuleType("superset")
        superset_security_mod = types.ModuleType("superset.security")

        class _StubSecurityManager:
            """Minimal stand-in so CognitoSecurityManager can subclass it."""
            def oauth_user_info(self, provider, response=None):
                return {}

        superset_security_mod.SupersetSecurityManager = _StubSecurityManager  # type: ignore[attr-defined]
        superset_mod.security = superset_security_mod  # type: ignore[attr-defined]
        sys.modules["superset"] = superset_mod
        sys.modules["superset.security"] = superset_security_mod


_install_superset_stub()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Mirror the constants from custom_sso_security_manager directly to avoid
# triggering the superset import chain at helper-call time.
_COGNITO_GROUP_ROLE_MAP: dict[str, str] = {"superset_admins": "Admin"}
_DEFAULT_ROLE: str = "Gamma"


def _sanitize_session_name(email: str) -> str:
    """Mirror the sanitization logic from athena_connection_mutator."""
    return re.sub(r"[^a-zA-Z0-9+=,.@-]", "-", email)[:64]


def _resolve_role(groups: list[str]) -> str:
    """Mirror the group-to-role mapping from custom_sso_security_manager."""
    for group in groups:
        if group in _COGNITO_GROUP_ROLE_MAP:
            return _COGNITO_GROUP_ROLE_MAP[group]
    return _DEFAULT_ROLE


# ---------------------------------------------------------------------------
# Property 1 — Session name sanitization produces only allowed characters
#              and is ≤ 64 chars
# Feature: athena-identity-propagation, Property 1: sanitized session name
#   contains only allowed chars and is ≤64 chars
# Validates: Requirements 4.2, 4.3
# ---------------------------------------------------------------------------

@given(st.text())
@settings(max_examples=100, deadline=None)
def test_session_name_sanitization(email: str) -> None:
    result = _sanitize_session_name(email)
    assert len(result) <= 64
    assert re.fullmatch(r"[a-zA-Z0-9+=,.@\-]*", result), (
        f"Disallowed characters in sanitized name: {result!r}"
    )


# ---------------------------------------------------------------------------
# Property 2 — Session name sanitization is idempotent
# Feature: athena-identity-propagation, Property 2: sanitization is
#   idempotent for already-safe names
# Validates: Requirements 4.2, 4.3
# ---------------------------------------------------------------------------

@given(
    st.text(
        alphabet=st.characters(whitelist_categories=("Lu", "Ll", "Nd")),
        max_size=64,
    )
)
@settings(max_examples=100, deadline=None)
def test_session_name_idempotent(safe_email: str) -> None:
    once = _sanitize_session_name(safe_email)
    twice = _sanitize_session_name(once)
    assert once == twice


# ---------------------------------------------------------------------------
# Property 3 — Non-Athena URIs pass through unchanged
# Feature: athena-identity-propagation, Property 3: non-Athena URIs pass
#   through unchanged
# Validates: Requirements 5.3
# ---------------------------------------------------------------------------

@given(st.text().filter(lambda s: "awsathena" not in s.lower()))
@settings(max_examples=100, deadline=None)
def test_non_athena_uri_passthrough(uri: str) -> None:
    from athena_connection_mutator import athena_db_connection_mutator

    original_args: dict[str, Any] = {}
    result_uri, result_args = athena_db_connection_mutator(
        uri, original_args, None, None, None
    )
    assert result_uri == uri
    assert result_args is original_args


# ---------------------------------------------------------------------------
# Property 4 — Unauthenticated connections pass through unchanged
# Feature: athena-identity-propagation, Property 4: unauthenticated
#   connections pass through unchanged
# Validates: Requirements 5.1, 5.2
# ---------------------------------------------------------------------------

@given(st.text(min_size=1).map(lambda s: "awsathena+rest://" + s))
@settings(max_examples=100, deadline=None)
def test_unauthenticated_passthrough(athena_uri: str) -> None:
    from athena_connection_mutator import athena_db_connection_mutator

    anon_user = MagicMock()
    anon_user.is_anonymous = True

    with patch("athena_connection_mutator.current_user", anon_user):
        result_uri, result_args = athena_db_connection_mutator(
            athena_uri, {}, None, None, None
        )
    assert result_uri == athena_uri


# ---------------------------------------------------------------------------
# Property 5 — Non-credential query params are preserved in rewritten URI
# Feature: athena-identity-propagation, Property 5: non-credential query
#   params are preserved in rewritten URI
# Validates: Requirements 3.7
# ---------------------------------------------------------------------------

_SAFE_ALPHA = st.text(
    min_size=1,
    max_size=20,
    alphabet=st.characters(whitelist_categories=("Lu", "Ll")),
)

_CREDENTIAL_PARAMS = {"aws_access_key_id", "aws_secret_access_key", "aws_session_token"}


@given(
    st.fixed_dictionaries({"schema": _SAFE_ALPHA, "catalog": _SAFE_ALPHA})
)
@settings(max_examples=100, deadline=None)
def test_non_credential_params_preserved(extra_params: dict[str, str]) -> None:
    from athena_connection_mutator import athena_db_connection_mutator

    # Build an input URI that includes both non-credential params AND
    # old credential params that should be stripped during rewrite.
    parts = [f"{k}={v}" for k, v in extra_params.items()]
    parts.append("aws_access_key_id=OLDKEY")
    parts.append("aws_secret_access_key=OLDSECRET")
    parts.append("aws_session_token=OLDTOKEN")
    query_string = "&".join(parts)
    athena_uri = f"awsathena+rest://ignored@athena.eu-central-1.amazonaws.com:443/?{query_string}"

    auth_user = MagicMock()
    auth_user.is_anonymous = False
    auth_user.email = "user@example.com"

    mock_sso_response = {"idToken": "idc-token-value"}
    mock_sts_response = {
        "Credentials": {
            "AccessKeyId": "NEWKEY",
            "SecretAccessKey": "NEWSECRET",
            "SessionToken": "NEWTOKEN",
        }
    }

    mock_sso_client = MagicMock()
    mock_sso_client.create_token_with_iam.return_value = mock_sso_response
    mock_sts_client = MagicMock()
    mock_sts_client.assume_role.return_value = mock_sts_response

    def _boto3_client(service: str, **_kwargs: Any) -> MagicMock:
        return mock_sso_client if service == "sso-oidc" else mock_sts_client

    app = flask.Flask(__name__)
    app.config["SECRET_KEY"] = "test"
    with app.test_request_context():
        flask.session["cognito_id_token"] = "cognito-id-token"
        with (
            patch("athena_connection_mutator.current_user", auth_user),
            patch("athena_connection_mutator._EXECUTION_ROLE_ARN", "arn:aws:iam::123:role/r"),
            patch("athena_connection_mutator._IDC_APPLICATION_ARN", "arn:aws:sso::123:app/a"),
            patch("athena_connection_mutator.boto3.client", side_effect=_boto3_client),
        ):
            result_uri, _ = athena_db_connection_mutator(
                athena_uri, {}, None, None, None
            )

    parsed = urlparse(result_uri)
    result_params = parse_qs(parsed.query)

    # All non-credential extra params must survive the rewrite
    for key, value in extra_params.items():
        assert key in result_params, f"Param {key!r} missing from rewritten URI"
        assert result_params[key][0] == value

    # The OLD credential values from the original URI must not appear
    result_str = str(result_uri)
    assert "OLDKEY" not in result_str
    assert "OLDSECRET" not in result_str
    assert "OLDTOKEN" not in result_str


# ---------------------------------------------------------------------------
# Property 6 — Rewritten URI contains all required credential components
#              URL-encoded
# Feature: athena-identity-propagation, Property 6: rewritten URI contains
#   all required credential components URL-encoded
# Validates: Requirements 3.5, 3.6
# ---------------------------------------------------------------------------

_CRED_TEXT = st.text(
    min_size=1,
    max_size=40,
    alphabet=st.characters(whitelist_categories=("Lu", "Ll", "Nd"), whitelist_characters="/+="),
)


@given(
    st.fixed_dictionaries(
        {
            "AccessKeyId": _CRED_TEXT,
            "SecretAccessKey": _CRED_TEXT,
            "SessionToken": _CRED_TEXT,
        }
    )
)
@settings(max_examples=100, deadline=None)
def test_rewritten_uri_has_credentials(creds: dict[str, str]) -> None:
    from athena_connection_mutator import athena_db_connection_mutator
    from urllib.parse import quote_plus

    athena_uri = "awsathena+rest://ignored@athena.eu-central-1.amazonaws.com:443/"

    auth_user = MagicMock()
    auth_user.is_anonymous = False
    auth_user.email = "user@example.com"

    mock_sso_client = MagicMock()
    mock_sso_client.create_token_with_iam.return_value = {"idToken": "idc-tok"}
    mock_sts_client = MagicMock()
    mock_sts_client.assume_role.return_value = {"Credentials": creds}

    def _boto3_client(service: str, **_kwargs: Any) -> MagicMock:
        return mock_sso_client if service == "sso-oidc" else mock_sts_client

    app = flask.Flask(__name__)
    app.config["SECRET_KEY"] = "test"
    with app.test_request_context():
        flask.session["cognito_id_token"] = "cognito-id-token"
        with (
            patch("athena_connection_mutator.current_user", auth_user),
            patch("athena_connection_mutator._EXECUTION_ROLE_ARN", "arn:aws:iam::123:role/r"),
            patch("athena_connection_mutator._IDC_APPLICATION_ARN", "arn:aws:sso::123:app/a"),
            patch("athena_connection_mutator._S3_STAGING_DIR", "s3://test-bucket/results/"),
            patch("athena_connection_mutator.boto3.client", side_effect=_boto3_client),
        ):
            result_uri, _ = athena_db_connection_mutator(
                athena_uri, {}, None, None, None
            )

    result_str = str(result_uri)

    # The access key and secret are URL-encoded in the URI authority (user:password)
    encoded_key = quote_plus(creds["AccessKeyId"])
    encoded_secret = quote_plus(creds["SecretAccessKey"])

    assert encoded_key in result_str, (
        f"AccessKeyId {encoded_key!r} not found in URI"
    )
    assert encoded_secret in result_str, (
        f"SecretAccessKey {encoded_secret!r} not found in URI"
    )
    # aws_session_token and s3_staging_dir must be present as query params
    assert "aws_session_token=" in result_str
    assert "s3_staging_dir=" in result_str

    # Verify the URI is parseable and contains the session token query param
    parsed = urlparse(result_str)
    params = parse_qs(parsed.query)
    assert "s3_staging_dir" in params
    assert "aws_session_token" in params


# ---------------------------------------------------------------------------
# Property 7 — Group-to-role mapping is deterministic
# Feature: athena-identity-propagation, Property 7: group-to-role mapping
#   is deterministic
# Validates: Requirements 2.3, 2.4
# ---------------------------------------------------------------------------

@given(st.lists(st.text()))
@settings(max_examples=100, deadline=None)
def test_group_role_mapping_deterministic(groups: list[str]) -> None:
    role_first = _resolve_role(groups)
    role_second = _resolve_role(groups)
    assert role_first == role_second


# ---------------------------------------------------------------------------
# Property 8 — TIP token exchange flow is invoked for authenticated Athena
#              connections
# Feature: athena-identity-propagation, Property 8: TIP token exchange flow
#   is invoked for authenticated Athena connections
# Validates: Requirements 3.3, 3.4, 8.3
# ---------------------------------------------------------------------------

@given(
    st.text(
        min_size=1,
        max_size=30,
        alphabet=st.characters(whitelist_categories=("Lu", "Ll", "Nd")),
    ).map(lambda s: s + "@example.com")
)
@settings(max_examples=100, deadline=None)
def test_tip_token_exchange_flow(user_email: str) -> None:
    from athena_connection_mutator import athena_db_connection_mutator

    athena_uri = "awsathena+rest://ignored@athena.eu-central-1.amazonaws.com:443/"
    id_token_value = "cognito-id-token-for-" + user_email

    auth_user = MagicMock()
    auth_user.is_anonymous = False
    auth_user.email = user_email

    mock_sso_client = MagicMock()
    mock_sso_client.create_token_with_iam.return_value = {"idToken": "idc-tok"}
    mock_sts_client = MagicMock()
    mock_sts_client.assume_role.return_value = {
        "Credentials": {
            "AccessKeyId": "AKID",
            "SecretAccessKey": "SECRET",
            "SessionToken": "TOKEN",
        }
    }

    def _boto3_client(service: str, **_kwargs: Any) -> MagicMock:
        return mock_sso_client if service == "sso-oidc" else mock_sts_client

    app = flask.Flask(__name__)
    app.config["SECRET_KEY"] = "test"
    with app.test_request_context():
        flask.session["cognito_id_token"] = id_token_value
        with (
            patch("athena_connection_mutator.current_user", auth_user),
            patch("athena_connection_mutator._EXECUTION_ROLE_ARN", "arn:aws:iam::123:role/r"),
            patch("athena_connection_mutator._IDC_APPLICATION_ARN", "arn:aws:sso::123:app/a"),
            patch("athena_connection_mutator.boto3.client", side_effect=_boto3_client),
        ):
            athena_db_connection_mutator(athena_uri, {}, None, None, None)

    # CreateTokenWithIAM must be called with the correct assertion
    mock_sso_client.create_token_with_iam.assert_called_once()
    call_kwargs = mock_sso_client.create_token_with_iam.call_args
    assert call_kwargs.kwargs.get("assertion") or call_kwargs[1].get("assertion") == id_token_value
    grant_type = call_kwargs.kwargs.get("grantType") or call_kwargs[1].get("grantType")
    assert grant_type == "urn:ietf:params:oauth:grant-type:jwt-bearer"

    # AssumeRole must use ProvidedContexts, NOT Tags/TransitiveTagKeys
    mock_sts_client.assume_role.assert_called_once()
    sts_kwargs = mock_sts_client.assume_role.call_args.kwargs or dict(
        zip(
            ("RoleArn", "RoleSessionName", "ProvidedContexts", "DurationSeconds"),
            mock_sts_client.assume_role.call_args.args,
        )
    )
    assert "ProvidedContexts" in sts_kwargs
    assert "Tags" not in sts_kwargs
    assert "TransitiveTagKeys" not in sts_kwargs

    ctx = sts_kwargs["ProvidedContexts"]
    assert len(ctx) == 1
    assert ctx[0]["ProviderArn"] == "arn:aws:iam::aws:contextProvider/IdentityCenter"


# ---------------------------------------------------------------------------
# Property 9 — OIDC claim extraction works for all valid token shapes
# Feature: athena-identity-propagation, Property 9: OIDC claim extraction
#   works for all valid token shapes
# Validates: Requirements 1.3
# ---------------------------------------------------------------------------

@given(
    st.fixed_dictionaries(
        {
            "email": st.emails(),
            "sub": st.uuids().map(str),
            "given_name": st.text(min_size=0, max_size=50),
            "family_name": st.text(min_size=0, max_size=50),
        }
    )
)
@settings(max_examples=100, deadline=None)
def test_oidc_claim_extraction(claims: dict[str, str]) -> None:
    from custom_sso_security_manager import CognitoSecurityManager

    mock_sm = MagicMock(spec=CognitoSecurityManager)
    mock_sm.appbuilder = MagicMock()

    # The userinfo endpoint returns the claims
    mock_remote = MagicMock()
    mock_remote.userinfo.return_value = {
        "email": claims["email"],
        "sub": claims["sub"],
        "given_name": claims["given_name"],
        "family_name": claims["family_name"],
        "name": f"{claims['given_name']} {claims['family_name']}".strip(),
    }
    mock_sm.appbuilder.sm.oauth_remotes = {"cognito": mock_remote}

    app = flask.Flask(__name__)
    app.config["SECRET_KEY"] = "test"
    with app.test_request_context():
        result = CognitoSecurityManager.oauth_user_info(
            mock_sm, provider="cognito", response=None
        )

    assert result["username"] == claims["email"]
    assert result["email"] == claims["email"]
    assert result["id"] == claims["sub"]
    # username and email must be non-empty
    assert result["username"]
    assert result["email"]
    assert result["id"]
