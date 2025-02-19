#!/bin/bash

FOLDER="kip-databases"

# Count total files
total=$(ls ${FOLDER}/*.yaml | wc -l)
current=0

# Process each file
for f in ${FOLDER}/*.yaml; do
    ((current++))
    echo "[$current/$total] Applying $f..."
    
    if kubectl delete -f "$f"; then
        echo "✅ Successfully deleted $f"
    fi
    
    # Small delay to prevent overwhelming the API server
    sleep 2
done

echo "Completed applying $total files"
