# Programmatic Access to DataZone-Governed Glue Catalogs

This document describes how to programmatically access AWS Glue Data Catalog resources managed by Amazon SageMaker Unified Studio (DataZone) using a Cognito identity token.

## Overview

SageMaker Unified Studio uses a multi-step credential chain to authorize users to query data catalogs. The JDBC connection string from the Studio UI reveals the required parameters and flow. This implementation replicates that flow in Python using boto3.

### JDBC Connection String (reference)

```
jdbc:athena://
  Region=eu-central-1;
  Workgroup=workgroup-568od5rs4kpsaz-543huadved7z0r;
  CredentialsProvider=DataZoneIdc;
  DataZoneDomainId=dzd-djkh2xy1il745n;
  DataZoneEnvironmentId=543huadved7z0r;
  DataZoneDomainRegion=eu-central-1;
  IdentityCenterIssuerUrl=https://identitycenter.amazonaws.com/ssoins-69877cf557cb578c
```

---

## Credential Chain

```
┌─────────────────┐
│  Cognito Token  │  (ID token from Cognito user pool)
└────────┬────────┘
         │ STS AssumeRoleWithWebIdentity
         ▼
┌─────────────────────────┐
│  Intermediary IAM Role  │  (OIDC-trusted role)
└────────┬────────────────┘
         │ SSO-OIDC CreateTokenWithIAM
         ▼
┌─────────────────────────┐
│  IdC Access Token       │  (Identity Center token)
└────────┬────────────────┘
         │ DataZone RedeemAccessToken (REST API)
         ▼
┌─────────────────────────────────┐
│  DomainExecutionRole Credentials│  (domain-scoped)
└────────┬────────────────────────┘
         │ DataZone GetEnvironmentCredentials
         ▼
┌─────────────────────────────────┐
│  Environment Credentials        │  (project-scoped role)
└────────┬────────────────────────┘
         │ Glue / Athena API calls
         ▼
┌─────────────────────────┐
│  Data Catalog Access    │
└─────────────────────────┘
```

---

## Roles and Permissions

### 1. Intermediary OIDC Role

**Role name:** `AndriSupersetPoc`  
**ARN:** `arn:aws:iam::666839000341:role/AndriSupersetPoc`

**Purpose:** Assumed via `AssumeRoleWithWebIdentity` using the Cognito ID token. Used to call `CreateTokenWithIAM` to exchange the Cognito token for an IdC access token.

**Trust policy:** Must trust the Cognito identity provider (issuer URL).

```json
{
  "Effect": "Allow",
  "Principal": { "Federated": "cognito-idp.eu-central-1.amazonaws.com/eu-central-1_K8UfZDRlf" },
  "Action": "sts:AssumeRoleWithWebIdentity",
  "Condition": {
    "StringEquals": {
      "cognito-idp.eu-central-1.amazonaws.com/eu-central-1_K8UfZDRlf:aud": "<cognito_client_id>"
    }
  }
}
```

**Required permissions:**
- `sso-oidc:CreateTokenWithIAM`

---

### 2. Domain Execution Role

**Role name:** `foen-dev-domain-execution-role`  
**ARN:** `arn:aws:sts::666839000341:assumed-role/foen-dev-domain-execution-role/user-<idc_user_id>`

**Purpose:** Returned by the `RedeemAccessToken` API. Acts as a broker to call `GetEnvironmentCredentials` on behalf of the authenticated user.

**Required permissions:**
- `datazone:GetEnvironmentCredentials`

This role is managed by SageMaker Unified Studio and is not directly configurable.

---

### 3. Environment Role (Project User Role)

**Role name:** `datazone_usr_role_<domain_id>_<environment_id>`  
**ARN:** `arn:aws:sts::666839000341:assumed-role/datazone_usr_role_568od5rs4kpsaz_543huadved7z0r/<user_id>@<env_id>`

**Purpose:** The final credentials used to access Glue, Athena, and other data services. Scoped to a specific DataZone project/environment.

**Permissions (managed by SageMaker Unified Studio):**
- `glue:GetDatabases`
- `glue:GetTables`
- `glue:GetTable`
- `glue:GetDatabase`
- `athena:StartQueryExecution`
- `athena:GetQueryExecution`
- `athena:GetQueryResults`
- `athena:ListWorkGroups`
- `s3:GetObject` / `s3:PutObject` (for Athena query results)
- Lake Formation data permissions (granted per user/group)

**Important:** The user's IdC identity must be a **member of the DataZone project** that owns the environment. Without project membership, `GetEnvironmentCredentials` returns `AccessDeniedException`.

---

### 4. Token Exchange Application

**ARN:** `arn:aws:sso::666839000341:application/ssoins-69877cf557cb578c/apl-6987d4bb15a48958`

**Purpose:** The IdC application configured to accept JWT bearer grants from the Cognito identity provider. Used as the `clientId` in `CreateTokenWithIAM`.

---

## API Calls (Step by Step)

### Step 1: Assume Intermediary Role

**Service:** AWS STS  
**API:** `AssumeRoleWithWebIdentity`  
**boto3:**

```python
sts = boto3.client("sts", region_name="eu-central-1")

response = sts.assume_role_with_web_identity(
    RoleArn="arn:aws:iam::666839000341:role/AndriSupersetPoc",
    RoleSessionName="GetIdCToken",
    WebIdentityToken=cognito_id_token,
    DurationSeconds=900,
)

credentials = response["Credentials"]
```

---

### Step 2: Exchange for IdC Access Token

**Service:** AWS SSO-OIDC  
**API:** `CreateTokenWithIAM`  
**boto3:**

```python
session = boto3.Session(
    aws_access_key_id=credentials["AccessKeyId"],
    aws_secret_access_key=credentials["SecretAccessKey"],
    aws_session_token=credentials["SessionToken"],
    region_name="eu-central-1",
)

sso_oidc = session.client("sso-oidc")

token_response = sso_oidc.create_token_with_iam(
    clientId="arn:aws:sso::666839000341:application/ssoins-69877cf557cb578c/apl-6987d4bb15a48958",
    grantType="urn:ietf:params:oauth:grant-type:jwt-bearer",
    assertion=cognito_id_token,
)

idc_access_token = token_response["accessToken"]
expires_in = token_response["expiresIn"]  # seconds
```

**Response fields:**
- `accessToken` — IdC access token (used in step 3)
- `idToken` — IdC ID token (contains `sts:identity_context`)
- `expiresIn` — token lifetime in seconds

---

### Step 3: Redeem Access Token

**Service:** Amazon DataZone  
**API:** `RedeemAccessToken` (REST endpoint, not in boto3)  
**Endpoint:** `POST https://datazone.<region>.api.aws/sso/redeem-token`

```python
import requests

url = "https://datazone.eu-central-1.api.aws/sso/redeem-token"
payload = {
    "domainId": "dzd-djkh2xy1il745n",
    "accessToken": idc_access_token,
}

response = requests.post(url, json=payload, headers={"Content-Type": "application/json"})
domain_creds = response.json()["credentials"]
```

**Response:**
```json
{
  "credentials": {
    "accessKeyId": "...",
    "secretAccessKey": "...",
    "sessionToken": "...",
    "expiration": 1777388670.0
  }
}
```

---

### Step 4: Get Environment Credentials

**Service:** Amazon DataZone  
**API:** `GetEnvironmentCredentials`  
**boto3:**

```python
session = boto3.Session(
    aws_access_key_id=domain_creds["accessKeyId"],
    aws_secret_access_key=domain_creds["secretAccessKey"],
    aws_session_token=domain_creds["sessionToken"],
    region_name="eu-central-1",
)

dz = session.client("datazone")

response = dz.get_environment_credentials(
    domainIdentifier="dzd-djkh2xy1il745n",
    environmentIdentifier="543huadved7z0r",
)

env_creds = {
    "accessKeyId": response["accessKeyId"],
    "secretAccessKey": response["secretAccessKey"],
    "sessionToken": response["sessionToken"],
    "expiration": response["expiration"],
}
```