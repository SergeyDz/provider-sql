#!/bin/bash

MICROSERVICES=("event-service" "bankapi" "apigw" "lp" "bi")
KIP_SUFFIXES=("kip0" "kip1" "kip2" "kip3" "kip4" "kipx" "kipy")
OUTPUT_DIR="../.tmp/kip-databases"

mkdir -p "$OUTPUT_DIR"

for ms in "${MICROSERVICES[@]}"; do
    for kip in "${KIP_SUFFIXES[@]}"; do
        # Use underscore for database and role names (used in PostgreSQL)
        DB_NAME="${ms//-/_}_${kip}"
        # Use hyphen for resource names (used in Kubernetes)
        RESOURCE_NAME="${ms//_/-}-${kip}"
        
        FILENAME="${OUTPUT_DIR}/${RESOURCE_NAME}.yaml"
        
        cat > "$FILENAME" << EOL
# filepath: /Users/sergii.dziuban/GitHub/provider-sql/.tmp/kip-databases/${RESOURCE_NAME}.yaml
apiVersion: postgresql.sql.crossplane.io/v1alpha1
kind: Database
metadata:
  name: ${RESOURCE_NAME}
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
  name: ${RESOURCE_NAME}-user
  annotations:
    crossplane.io/external-name: ${DB_NAME}_user
  labels:
    crossplane.io/claim-name: postgresdb-${ms//_/-}
    crossplane.io/claim-namespace: ${ms//_/-}
# ...rest of the template...
EOL

        echo "Generated configuration for ${RESOURCE_NAME}"
    done
done

echo "Generated all database configurations in ${OUTPUT_DIR}"
echo "Total configurations: $((${#MICROSERVICES[@]} * ${#KIP_SUFFIXES[@]}))"
