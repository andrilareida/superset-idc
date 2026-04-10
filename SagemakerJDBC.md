# Connecting Amazon SageMaker Unified Studio to Apache Superset via JDBC

This guide covers how to connect external applications — including Apache Superset — to
Amazon SageMaker Unified Studio data using the Athena JDBC driver.

## Overview

Amazon SageMaker Unified Studio supports authentication through the **Amazon Athena JDBC
driver**, enabling users to query subscribed data lake assets from external SQL and
analytics tools. Authentication is handled via **IAM Identity Center (SSO)** or **IAM
credentials**.

## Prerequisites

- An active AWS account with a SageMaker Unified Studio domain configured
- At least one SageMaker Unified Studio project with subscribed data assets
- The latest [Amazon Athena JDBC driver (v3.x)](https://docs.aws.amazon.com/athena/latest/ug/connect-with-jdbc.html)
- IAM Identity Center (IDC) or IAM credentials for authentication

## Step 1: Obtain the JDBC Connection URL

1. Log in to Amazon SageMaker Unified Studio using your SSO or AWS credentials.
2. Choose **Select project** from the top navigation and open the project containing
   your data.
3. On the **Project overview** page, choose the **JDBC connection details** tab.
4. Select your authentication method (**Using IDC auth** or **Using IAM auth**).
5. Copy the **JDBC connection URL** or the individual connection parameters.

The JDBC URL contains these key parameters:

| Parameter                  | Description                                              |
| -------------------------- | -------------------------------------------------------- |
| `CredentialsProvider`      | Credentials provider class for AWS authentication        |
| `DataZoneDomainId`         | ID of your Amazon DataZone domain                        |
| `DataZoneDomainRegion`     | AWS Region where your domain is hosted                   |
| `DataZoneEnvironmentId`    | ID of your DefaultDataLake environment                   |
| `IdentityCenterIssuerUrl`  | Issuer URL used by IAM Identity Center for token issuance|
| `OutputLocation`           | S3 path for storing Athena query results                 |
| `Region`                   | AWS Region where the environment is created              |
| `Workgroup`                | Amazon Athena workgroup for the environment              |
| `ListenPort` *(optional)*  | Local port for the IDC auth callback (any free port)     |

## Step 2: Verify Connectivity with a SQL Client (Optional)

Before configuring Superset, you can verify the connection using a desktop SQL client
like DBeaver or SQL Workbench/J:

1. Install the Athena JDBC 3.x driver in your client.
2. Create a new connection using the Athena driver.
3. Paste the JDBC URL or enter the individual parameters from Step 1.
4. Test the connection — you will be redirected to IAM Identity Center to authenticate.
5. After sign-in, authorize the **DataZoneAuthPlugin** when prompted.

If the connection succeeds, your subscribed data assets will be visible and queryable.

## Step 3: Integrate with Apache Superset

Superset connects to Athena using the **PyAthena** Python driver (not the Java JDBC
driver directly). The connection uses SQLAlchemy URIs.

### Install the Driver

Make sure `pyathena` is installed in your Superset environment:

```bash
pip install "pyathena[pandas]"
```

### Connection String Formats

Superset's Athena engine spec supports two drivers:

**PyAthena REST (recommended):**

```
awsathena+rest://{aws_access_key_id}:{aws_secret_access_key}@athena.{region_name}.amazonaws.com/{schema_name}?s3_staging_dir={s3_staging_dir}
```

**PyAthenaJDBC:**

```
awsathena+jdbc://{aws_access_key_id}:{aws_secret_access_key}@athena.{region_name}.amazonaws.com/{schema_name}?s3_staging_dir={s3_staging_dir}
```

### Configure the Database in Superset

1. In Superset, go to **Settings → Database Connections → + Database**.
2. Select **Amazon Athena** from the supported databases list.
3. Fill in the SQLAlchemy URI using the parameters from your SageMaker Unified Studio
   JDBC connection details:

   ```
   awsathena+rest://{aws_access_key_id}:{aws_secret_access_key}@athena.{region}.amazonaws.com/{schema_name}?s3_staging_dir=s3://{output_location}&catalog_name={catalog_name}&work_group={workgroup}
   ```

   Replace the placeholders:
   - `{aws_access_key_id}` / `{aws_secret_access_key}` — your IAM credentials
   - `{region}` — the `DataZoneDomainRegion` from the JDBC connection details
   - `{schema_name}` — the database/schema containing your subscribed assets
   - `{output_location}` — the `OutputLocation` S3 path from the JDBC details
   - `{catalog_name}` — the Glue catalog name (typically `AwsDataCatalog`)
   - `{workgroup}` — the `Workgroup` from the JDBC connection details

4. Choose **Test Connection** to verify.
5. Choose **Connect** to save.

### Using IAM Role-Based Authentication (Recommended for Production)

Instead of embedding access keys in the connection string, configure Superset to use
IAM role credentials. This is the preferred approach when Superset runs on AWS
infrastructure (EC2, ECS, EKS):

```
awsathena+rest://:@athena.{region}.amazonaws.com/{schema_name}?s3_staging_dir=s3://{output_location}&work_group={workgroup}
```

When the access key and secret are omitted, PyAthena falls back to the standard AWS
credential chain (environment variables, instance profile, ECS task role, etc.). Ensure
the IAM role has permissions to:

- Execute Athena queries (`athena:StartQueryExecution`, `athena:GetQueryResults`, etc.)
- Access the S3 output location
- Access the Glue Data Catalog
- Access the SageMaker Unified Studio / DataZone resources if using governed data

### Using a Connection Mutator (Advanced)

If you need to dynamically inject credentials or modify connection parameters, Superset
supports a `DB_CONNECTION_MUTATOR` in `superset_config.py`. This is useful for
integrating with STS temporary credentials or custom auth flows:

```python
def DB_CONNECTION_MUTATOR(uri, params, effective_user, security_manager, source):
    if uri.get_backend_name() == "awsathena":
        # Inject temporary credentials from STS, environment, etc.
        pass
    return uri, params
```

## Authentication Considerations

| Method              | Use Case                                    | Notes                                    |
| ------------------- | ------------------------------------------- | ---------------------------------------- |
| IAM Access Keys     | Development / testing                       | Embed in URI; rotate regularly           |
| IAM Role            | Production on AWS infra                     | Omit keys; uses credential chain         |
| IDC (SSO)           | Interactive desktop tools (DBeaver, Tableau) | Requires browser-based auth flow         |
| STS Temporary Creds | Programmatic with short-lived tokens        | Use connection mutator or env variables  |

> **Note:** The IDC/SSO browser-based authentication flow used by the JDBC driver in
> desktop tools is not directly compatible with Superset's server-side connection model.
> For Superset, use IAM credentials or IAM role-based authentication instead.

## Troubleshooting

- **Connection timeout** — Verify that Superset's host can reach
  `athena.{region}.amazonaws.com` on port 443. Check VPC/security group settings.
- **Access denied** — Confirm the IAM user/role has the required Athena, S3, Glue, and
  DataZone permissions.
- **Schema not visible** — Ensure the `catalog_name` and `schema_name` match the
  subscribed assets in your SageMaker Unified Studio project.
- **PyAthena not found** — Run `pip install "pyathena[pandas]"` in the Superset
  virtualenv and restart the server.

## References

- [SageMaker Unified Studio — Query with JDBC](https://docs.aws.amazon.com/sagemaker-unified-studio/latest/userguide/query-with-jdbc.html)
- [Power up your analytics with SageMaker Unified Studio integration](https://aws.amazon.com/blogs/big-data/power-up-your-analytics-with-amazon-sagemaker-unified-studio-integration-with-tableau-power-bi-and-more/)
- [Amazon Athena JDBC Driver](https://docs.aws.amazon.com/athena/latest/ug/connect-with-jdbc.html)
- [Superset — Installing Database Drivers](https://superset.apache.org/docs/databases/installing-database-drivers)
