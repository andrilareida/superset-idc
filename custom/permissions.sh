 #!/usr/bin/env bash
DOMAIN_ID="dzd-djkh2xy1il745n"
PROJECT_ID="cxqfn5an30d5e3"
BLUEPRINT_ID="4dssk42qp8k7nv"
#aws datazone list-environments --domain-identifier dzd-djkh2xy1il745n --project-identifier cxqfn5an30d5e3



aws lakeformation grant-permissions \
    --principal DataLakePrincipalIdentifier=arn:aws:iam::666839000341:role/AndriSuperSetPocAthenaExecutionRole \
    --permissions "SELECT" "DESCRIBE" \
    --resource '{ "Table": { "DatabaseName": "*", "TableWildcard": {} } }'

#Does not work
aws datazone get-project \
  --region eu-central-1 \
  --domain-identifier dzd-djkh2xy1il745n \
  --identifier cxqfn5an30d5e3

aws datazone create-environment-profile \
  --region eu-central-1 \
  --domain-identifier $DOMAIN_ID \
  --project-identifier $PROJECT_ID \
  --name "superset-athena" \
  --environment-blueprint-identifier $BLUEPRINT_ID \
  --user-parameters '[{"name":"roleArn","value":"arn:aws:iam::666839000341:role/AndriSuperSetPocAthenaExecutionRole"}]'



  # 1. Catalog-level (fixes CATALOG_NOT_FOUND)
aws lakeformation grant-permissions --region eu-central-1 --cli-input-json '{
  "Principal": {
    "DataLakePrincipalIdentifier": "arn:aws:iam::666839000341:role/AndriSuperSetPocAthenaExecutionRole"
  },
  "Resource": {
    "Catalog": {
      "Id": "666839000341:s3tablescatalog/foen-dev-data-published"
    }
  },
  "Permissions": ["ALL"],
  "PermissionsWithGrantOption": ["ALL"]
}'

# 2. Database-level
aws lakeformation grant-permissions --region eu-central-1 --cli-input-json '{
  "Principal": {
    "DataLakePrincipalIdentifier": "arn:aws:iam::666839000341:role/AndriSuperSetPocAthenaExecutionRole"
  },
  "Resource": {
    "Database": {
      "CatalogId": "666839000341:s3tablescatalog/foen-dev-data-published",
      "Name": "*"
    }
  },
  "Permissions": ["SELECT" "DESCRIBE"],
  "PermissionsWithGrantOption": []
}'

# 3. Table-level
aws lakeformation grant-permissions --region eu-central-1 --cli-input-json '{
  "Principal": {
    "DataLakePrincipalIdentifier": "arn:aws:iam::666839000341:role/AndriSuperSetPocAthenaExecutionRole"
  },
  "Resource": {
    "Table": {
      "CatalogId": "666839000341:s3tablescatalog/foen-dev-data-published",
      "DatabaseName": "*",
      "TableWildcard": {}
    }
  },
  "Permissions": ["SELECT", "DESCRIBE"],
  "PermissionsWithGrantOption": ["SELECT", "DESCRIBE"]
}'