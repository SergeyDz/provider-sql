#!/bin/bash

FOLDER="kip-databases"

# Count total files
total=$(ls ${FOLDER}/*.yaml | wc -l)
current=0

# Process each file
for f in ${FOLDER}/*.yaml; do
    ((current++))
    echo "[$current/$total] Applying $f..."
    
    if kubectl apply -f "$f"; then
        echo "✅ Successfully applied $f"
    else
        echo "❌ Failed to apply $f"
        echo "Continue? (y/n)"
        read answer
        if [ "$answer" != "y" ]; then
            echo "Aborting..."
            exit 1
        fi
    fi
    
    # Small delay to prevent overwhelming the API server
    sleep 2
done

echo "Completed applying $total files"
