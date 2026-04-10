# Connecting Amazon SageMaker Unified Studio to Apache Superset via Athena JDBC

This guide covers how to connect Apache Superset (running in Docker) to Amazon SageMaker
Unified Studio governed data using the Athena JDBC driver with AWS Identity Center (IDC)
authentication.

## Overview

SageMaker Unified Studio supports authentication through the Amazon Athena JDBC driver,
enabling external tools to query subscribed data lake assets. Superset uses
[PyAthenaJDBC](https://pypi.org/project/PyAthenaJDBC/) — a Python DB-API 2.0 wrapper
around the Amazon Athena JDBC driver — which requires a **Java runtime** and the
**Athena JDBC JAR** to be present in the container.

Authentication is handled via **AWS Identity Center (IDC)** using Trusted Identity
Propagation (TIP). The existing connection mutator in this repository exchanges each
user's Cognito ID token for Identity Center credentials, then assumes a role via STS
with the user's identity context. This enables per-user, governed access to SageMaker
Unified Studio data through Lake Formation.

## Prerequisites

- A running Superset Docker Compose environment (see `docker-compose.yml`)
- An AWS account with:
  - A SageMaker Unified Studio domain configured with IAM Identity Center
  - A project with subscribed data assets
  - A Cognito User Pool integrated with Identity Center as a Trusted Token Issuer
  - An Identity Center application ARN for `CreateTokenWithIAM`
  - An execution role with Lake Formation / Athena / S3 / Glue permissions
- The JDBC connection details from the SageMaker Unified Studio portal

## Step 1: Obtain the JDBC Connection Details

1. Log in to SageMaker Unified Studio with your SSO credentials.
2. Open the project containing your subscribed data assets.
3. On the **Project overview** page, choose the **JDBC connection details** tab.
4. Select **Using IDC auth**.
5. Copy the JDBC connection URL or the individual parameters:

| Parameter                  | Description                                               |
| -------------------------- | --------------------------------------------------------- |
| `CredentialsProvider`      | Credentials provider class for IDC authentication         |
| `DataZoneDomainId`         | ID of your Amazon DataZone domain                         |
| `DataZoneDomainRegion`     | AWS Region where your domain is hosted                    |
| `DataZoneEnvironmentId`    | ID of your DefaultDataLake environment                    |
| `IdentityCenterIssuerUrl`  | Issuer URL for IAM Identity Center token issuance         |
| `OutputLocation`           | S3 path for storing Athena query results                  |
| `Region`                   | AWS Region where the environment is created               |
| `Workgroup`                | Amazon Athena workgroup for the environment               |

## Step 2: Install Java and the Athena JDBC Driver in the Docker Container

`PyAthenaJDBC` delegates to the official Amazon Athena JDBC JAR via
[JPype](https://jpype.readthedocs.io/). The container needs:

1. A Java Runtime Environment (JRE)
2. The Athena JDBC driver JAR file
3. The `PyAthenaJDBC` Python package

### 2a. Add Java to the Dockerfile

In the `dev` stage of the `Dockerfile`, add `default-jre-headless` to the apt-install
step:

```dockerfile
######################################################################
FROM python-common AS dev

# Debian libs needed for dev
RUN /app/docker/apt-install.sh \
    git \
    pkg-config \
    default-libmysqlclient-dev \
    default-jre-headless          # <-- Java runtime for PyAthenaJDBC
```

If you are building the `lean` stage for production, add the same package there.

### 2b. Download the Athena JDBC Driver JAR

Download the latest Athena JDBC v3.x driver from the
[AWS Athena JDBC documentation](https://docs.aws.amazon.com/athena/latest/ug/connect-with-jdbc.html).

Place the JAR in a `docker/jdbc-drivers/` directory:

```
docker/jdbc-drivers/
└── AthenaJDBC43.jar
```

### 2c. Mount the JAR into the Container

Add a volume mount in `docker-compose.yml` under the `x-superset-volumes` anchor:

```yaml
x-superset-volumes:
  &superset-volumes
  - ./docker:/app/docker
  - ./superset:/app/superset
  # ... existing mounts ...
  - ./docker/jdbc-drivers:/app/jdbc-drivers   # <-- Athena JDBC JAR
```

Alternatively, add a `COPY` in the Dockerfile:

```dockerfile
COPY docker/jdbc-drivers/*.jar /app/jdbc-drivers/
```

### 2d. Set the CLASSPATH Environment Variable

`PyAthenaJDBC` (via JPype) needs to find the JAR on the Java classpath. Add the
environment variable to the superset services in `docker-compose.yml`:

```yaml
services:
  superset:
    environment:
      CLASSPATH: "/app/jdbc-drivers/AthenaJDBC43.jar"
```

Apply the same to `superset-worker` and `superset-init` if they also execute Athena
queries. Or set it in `docker/.env-local`:

```bash
CLASSPATH=/app/jdbc-drivers/AthenaJDBC43.jar
```

### 2e. Install the PyAthenaJDBC Python Package

Add `PyAthenaJDBC` to `requirements/development.txt`:

```
PyAthenaJDBC
```

Or install manually inside the running container for quick testing:

```bash
docker compose exec superset uv pip install PyAthenaJDBC
```

### 2f. Rebuild and Verify

```bash
docker compose build superset
docker compose up -d
```

Verify Java is available:

```bash
docker compose exec superset java -version
```

Verify PyAthenaJDBC is installed:

```bash
docker compose exec superset python -c "import pyathenajdbc; print('OK')"
```

## Step 3: Configure IDC Environment Variables

The connection mutator at `docker/pythonpath_dev/athena_connection_mutator.py` handles
the IDC authentication flow. It requires these environment variables in
`docker/.env-local`:

```bash
# Identity Center application ARN for CreateTokenWithIAM
IDC_APPLICATION_ARN=arn:aws:sso::123456789012:application/ssoins-.../apl-...

# Execution role assumed via STS with the user's identity context
ATHENA_EXECUTION_ROLE_ARN=arn:aws:iam::123456789012:role/datazone_usr_role_...

# S3 path for Athena query results (from JDBC connection details: OutputLocation)
ATHENA_S3_STAGING_DIR=s3://your-bucket/athena-results/

# AWS Region (from JDBC connection details: Region)
AWS_REGION=eu-central-1

# Service role that Superset assumes before calling CreateTokenWithIAM and STS
SUPERSET_SERVICE_ROLE_ARN=arn:aws:iam::123456789012:role/superset-service-role

# Cognito app client credentials (for token refresh)
COGNITO_CLIENT_ID=your-cognito-client-id
COGNITO_CLIENT_SECRET=your-cognito-client-secret
```

The `OutputLocation`, `Region`, and `Workgroup` values from the JDBC connection details
(Step 1) map directly to `ATHENA_S3_STAGING_DIR` and `AWS_REGION`.

## Step 4: Configure the Database Connection in Superset

The connection mutator intercepts all `awsathena` connections and rewrites the URI with
per-user temporary credentials from the IDC/TIP flow. This means the initial database
connection string only needs the Athena endpoint and schema — the mutator injects
credentials at query time.

### Connection String

```
awsathena+jdbc://:@athena.{region}.amazonaws.com/{schema_name}?s3_staging_dir=s3%3A//{output_location}&work_group={workgroup}&catalog_name={catalog_name}
```

Replace the placeholders with values from your JDBC connection details:
- `{region}` — the `DataZoneDomainRegion` / `Region`
- `{schema_name}` — the database/schema containing your subscribed assets
- `{output_location}` — the `OutputLocation` S3 path (URL-encode `s3://` → `s3%3A//`)
- `{workgroup}` — the `Workgroup` from the JDBC connection details
- `{catalog_name}` — the Glue catalog name (typically `AwsDataCatalog`)

### Add the Database via the Superset UI

1. Go to **Settings → Database Connections → + Database**.
2. Select **Amazon Athena**.
3. Paste the connection string above into the SQLAlchemy URI field.
4. Click **Test Connection** to verify.
5. Click **Connect** to save.

The connection mutator (`DB_CONNECTION_MUTATOR`) is already wired up in
`docker/pythonpath_dev/superset_config_docker.py`:

```python
from athena_connection_mutator import athena_db_connection_mutator
DB_CONNECTION_MUTATOR = athena_db_connection_mutator
```

## How the IDC Authentication Flow Works

When a user executes a query against the Athena database:

1. The connection mutator reads the user's **Cognito ID token** from the Flask session
   (or Redis for Celery workers).
2. It exchanges the Cognito token for an **Identity Center token** via
   `sso-oidc:CreateTokenWithIAM`, extracting the `sts:identity_context` claim.
3. It calls **`sts:AssumeRole`** on the execution role with the identity context in
   `ProvidedContexts`, so Lake Formation resolves the user's identity for row- and
   column-level security.
4. The SQLAlchemy URI is **rewritten** with the temporary STS credentials.
5. The query executes against Athena with the user's governed permissions.

Credentials are cached in Redis and reused until they approach expiry (~58 min).

## Troubleshooting

- **`No Java runtime present`** — Java is not installed in the container. Add
  `default-jre-headless` to the Dockerfile apt-install step and rebuild.
- **`ClassNotFoundException` or JAR not found** — The `CLASSPATH` environment variable
  is not set or points to the wrong path. Verify with
  `docker compose exec superset echo $CLASSPATH` and check the JAR exists at that path.
- **`ModuleNotFoundError: No module named 'pyathenajdbc'`** — `PyAthenaJDBC` is not
  installed. Run `uv pip install PyAthenaJDBC` inside the container or add it to
  requirements.
- **`InvalidGrantException` during token exchange** — The Cognito ID token `aud` claim
  does not match the Trusted Token Issuer audience in Identity Center, or the token is
  expired. Re-authenticate via the Superset login page.
- **`AccessDeniedException` on STS AssumeRole** — The execution role trust policy does
  not allow the service role to assume it with `ProvidedContexts`. Check the IAM trust
  policy.
- **Connection timeout** — Verify the container can reach
  `athena.{region}.amazonaws.com:443`. Check VPC/security group settings.
- **Schema not visible** — Ensure `catalog_name` and `schema_name` match the subscribed
  assets in your SageMaker Unified Studio project.
- **Stale credentials after session expiry** — The mutator attempts to refresh the
  Cognito token via `REFRESH_TOKEN_AUTH`. If refresh fails, the user must log in again.

## References

- [SageMaker Unified Studio — Query with JDBC](https://docs.aws.amazon.com/sagemaker-unified-studio/latest/userguide/query-with-jdbc.html)
- [Power up your analytics with SageMaker Unified Studio](https://aws.amazon.com/blogs/big-data/power-up-your-analytics-with-amazon-sagemaker-unified-studio-integration-with-tableau-power-bi-and-more/)
- [Amazon Athena JDBC Driver](https://docs.aws.amazon.com/athena/latest/ug/connect-with-jdbc.html)
- [PyAthenaJDBC on PyPI](https://pypi.org/project/PyAthenaJDBC/)
