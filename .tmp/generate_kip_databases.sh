#!/bin/bash

MICROSERVICES=("event_service" "bankapi")
KIP_SUFFIXES=("kip0" "kip1")
OUTPUT_DIR="../.tmp/kip-databases"

mkdir -p "$OUTPUT_DIR"

for ms in "${MICROSERVICES[@]}"; do
    for kip in "${KIP_SUFFIXES[@]}"; do
        # Database name uses underscores
        DB_NAME="${ms}_${kip}"
        # K8s resource name uses hyphens (convert underscores to hyphens)
        K8S_NAME="${ms//_/-}-${kip}"
        FILENAME="${OUTPUT_DIR}/${DB_NAME}.yaml"
        
        cat > "$FILENAME" << EOL
# filepath: /Users/sergii.dziuban/GitHub/provider-sql/.tmp/kip-databases/${DB_NAME}.yaml
apiVersion: postgresql.sql.crossplane.io/v1alpha1
kind: Database
metadata:
  name: ${K8S_NAME}
  annotations:
    crossplane.io/external-name: ${DB_NAME}
  labels:
    crossplane.io/claim-name: postgresdb-${ms//_/-}
    crossplane.io/claim-namespace: ${ms//_/-}
spec:
  deletionPolicy: Delete
  forProvider:
    allowConnections: true
    connectionLimit: -1
    encoding: UTF8
    isTemplate: false
    lcCType: en_US.UTF-8
    lcCollate: en_US.UTF-8
    owner: ${DB_NAME}_user
    tablespace: pg_default
  managementPolicies:
  - '*'
  providerConfigRef:
    name: default-sql-postgres-provider-config
---
apiVersion: postgresql.sql.crossplane.io/v1alpha1
kind: Role
metadata:
  name: ${K8S_NAME}-user
  annotations:
    crossplane.io/external-name: ${DB_NAME}_user
  labels:
    crossplane.io/claim-name: postgresdb-${ms//_/-}
    crossplane.io/claim-namespace: ${ms//_/-}
spec:
  deletionPolicy: Orphan
  forProvider:
    connectionLimit: -1
    passwordSecretRef:
      key: password
      name: ${K8S_NAME}-user
      namespace: ${ms//_/-}
    privileges:
      bypassRls: false
      createDb: false
      createRole: false
      inherit: true
      login: true
      replication: false
      superUser: false
  managementPolicies:
  - '*'
  providerConfigRef:
    name: default-sql-postgres-provider-config
  writeConnectionSecretToRef:
    name: postgresdb-${K8S_NAME}-owner
    namespace: default
---
apiVersion: postgresql.sql.crossplane.io/v1alpha1
kind: Role
metadata:
  name: ${K8S_NAME}-app-user
  annotations:
    crossplane.io/external-name: ${DB_NAME}_app_user
  labels:
    crossplane.io/claim-name: postgresdb-${ms//_/-}
    crossplane.io/claim-namespace: ${ms//_/-}
spec:
  deletionPolicy: Orphan
  forProvider:
    connectionLimit: -1
    passwordSecretRef:
      key: password
      name: ${K8S_NAME}-app-user
      namespace: ${ms//_/-}
    privileges:
      bypassRls: false
      createDb: false
      createRole: false
      inherit: true
      login: true
      replication: false
      superUser: false
  managementPolicies:
  - '*'
  providerConfigRef:
    name: default-sql-postgres-provider-config
  writeConnectionSecretToRef:
    name: postgresdb-${K8S_NAME}-app-user
    namespace: default
---
apiVersion: v1
kind: Secret
metadata:
  name: ${K8S_NAME}-user
  namespace: ${ms//_/-}
type: Opaque
data:
  password: aGVsbG93b3JsZA==
---
apiVersion: v1
kind: Secret
metadata:
  name: ${K8S_NAME}-app-user
  namespace: ${ms//_/-}
type: Opaque
data:
  password: aGVsbG93b3JsZA==
---
apiVersion: postgresql.sql.crossplane.io/v1alpha1
kind: Grant
metadata:
  name: ${K8S_NAME}-owner-connect
spec:
  deletionPolicy: Orphan
  providerConfigRef:
    name: default-sql-postgres-provider-config
  forProvider:
    database: ${DB_NAME}
    databaseRef:
      name: ${K8S_NAME}
    privileges:
    - CONNECT
    revokePublicOnDb: true
    role: ${DB_NAME}_user
    roleRef:
      name: ${K8S_NAME}-user
    withOption: GRANT
  managementPolicies:
  - '*'
---
apiVersion: postgresql.sql.crossplane.io/v1alpha1
kind: Grant
metadata:
  name: ${K8S_NAME}-app-user-connect
spec:
  deletionPolicy: Orphan
  providerConfigRef:
    name: default-sql-postgres-provider-config
  forProvider:
    database: ${DB_NAME}
    databaseRef:
      name: ${K8S_NAME}
    privileges:
    - CONNECT
    revokePublicOnDb: true
    role: ${DB_NAME}_app_user
    roleRef:
      name: ${K8S_NAME}-app-user
    withOption: GRANT
  managementPolicies:
  - '*'
---
apiVersion: postgresql.sql.crossplane.io/v1alpha1
kind: Schema
metadata:
  name: ${K8S_NAME}-public-schema
  annotations:
    crossplane.io/external-name: public
spec:
  deletionPolicy: Orphan
  forProvider:
    database: ${DB_NAME}
    databaseRef:
      name: ${K8S_NAME}
    role: ${DB_NAME}_user
    roleRef:
      name: ${K8S_NAME}-user
  providerConfigRef:
    name: default-sql-postgres-provider-config
---
apiVersion: postgresql.sql.crossplane.io/v1alpha1
kind: Schema
metadata:
  name: ${K8S_NAME}-next-schema
  annotations:
    crossplane.io/external-name: next
spec:
  deletionPolicy: Orphan
  forProvider:
    database: ${DB_NAME}
    databaseRef:
      name: ${K8S_NAME}
    role: ${DB_NAME}_user
    roleRef:
      name: ${K8S_NAME}-user
  providerConfigRef:
    name: default-sql-postgres-provider-config
---
apiVersion: postgresql.sql.crossplane.io/v1alpha1
kind: Grant
metadata:
  name: ${K8S_NAME}-schema-usage
spec:
  deletionPolicy: Orphan
  providerConfigRef:
    name: default-sql-postgres-provider-config
  forProvider:
    privileges:
      - USAGE
    roleRef:
      name: ${K8S_NAME}-app-user
    schemaRef:
      name: ${K8S_NAME}-public-schema
    databaseRef:
      name: ${K8S_NAME}
---
apiVersion: postgresql.sql.crossplane.io/v1alpha1
kind: Grant
metadata:
  name: ${K8S_NAME}-next-schema-usage
spec:
  deletionPolicy: Orphan
  providerConfigRef:
    name: default-sql-postgres-provider-config
  forProvider:
    privileges:
      - USAGE
    roleRef:
      name: ${K8S_NAME}-app-user
    schemaRef:
      name: ${K8S_NAME}-next-schema
    databaseRef:
      name: ${K8S_NAME}
---
apiVersion: postgresql.sql.crossplane.io/v1alpha1
kind: Grant
metadata:
  name: ${K8S_NAME}-table-privileges
spec:
  deletionPolicy: Orphan
  providerConfigRef:
    name: default-sql-postgres-provider-config
  forProvider:
    privileges:
      - SELECT
      - INSERT
      - UPDATE
      - DELETE
      - REFERENCES
    roleRef:
      name: ${K8S_NAME}-app-user
    schemaRef:
      name: ${K8S_NAME}-public-schema
    databaseRef:
      name: ${K8S_NAME}
    onTables: true
---
apiVersion: postgresql.sql.crossplane.io/v1alpha1
kind: Grant
metadata:
  name: ${K8S_NAME}-next-table-privileges
spec:
  deletionPolicy: Orphan
  providerConfigRef:
    name: default-sql-postgres-provider-config
  forProvider:
    privileges:
      - SELECT
      - INSERT
      - UPDATE
      - DELETE
      - REFERENCES
    roleRef:
      name: ${K8S_NAME}-app-user
    schemaRef:
      name: ${K8S_NAME}-next-schema
    databaseRef:
      name: ${K8S_NAME}
    onTables: true
---
apiVersion: postgresql.sql.crossplane.io/v1alpha1
kind: Grant
metadata:
  name: ${K8S_NAME}-sequence-privileges
spec:
  deletionPolicy: Orphan
  providerConfigRef:
    name: default-sql-postgres-provider-config
  forProvider:
    privileges:
      - USAGE
      - SELECT
    roleRef:
      name: ${K8S_NAME}-app-user
    schemaRef:
      name: ${K8S_NAME}-public-schema
    databaseRef:
      name: ${K8S_NAME}
    onSequences: true
---
apiVersion: postgresql.sql.crossplane.io.v1alpha1
kind: Grant
metadata:
  name: ${K8S_NAME}-next-sequence-privileges
spec:
  deletionPolicy: Orphan
  providerConfigRef:
    name: default-sql-postgres-provider-config
  forProvider:
    privileges:
      - USAGE
      - SELECT
    roleRef:
      name: ${K8S_NAME}-app-user
    schemaRef:
      name: ${K8S_NAME}-next-schema
    databaseRef:
      name: ${K8S_NAME}
    onSequences: true
---
apiVersion: postgresql.sql.crossplane.io/v1alpha1
kind: Grant
metadata:
  name: ${K8S_NAME}-function-privileges
spec:
  deletionPolicy: Orphan
  providerConfigRef:
    name: default-sql-postgres-provider-config
  forProvider:
    privileges:
      - EXECUTE
    roleRef:
      name: ${K8S_NAME}-app-user
    schemaRef:
      name: ${K8S_NAME}-public-schema
    databaseRef:
      name: ${K8S_NAME}
    onFunctions: true
---
apiVersion: postgresql.sql.crossplane.io/v1alpha1
kind: Grant
metadata:
  name: ${K8S_NAME}-next-function-privileges
spec:
  deletionPolicy: Orphan
  providerConfigRef:
    name: default-sql-postgres-provider-config
  forProvider:
    privileges:
      - EXECUTE
    roleRef:
      name: ${K8S_NAME}-app-user
    schemaRef:
      name: ${K8S_NAME}-next-schema
    databaseRef:
      name: ${K8S_NAME}
    onFunctions: true
EOL

        echo "Generated configuration for ${DB_NAME}"
    done
done

echo "Generated all database configurations in ${OUTPUT_DIR}"
echo "Total configurations: $((${#MICROSERVICES[@]} * ${#KIP_SUFFIXES[@]}))"
