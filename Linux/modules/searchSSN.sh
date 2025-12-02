#!/bin/bash

echo "Searching for SSN Patterns"
rootdir="/home/"
ssn_pattern='[0-9]\{3\}-[0-9]\{2\}-[0-9]\{4\}'

echo "Scanning $rootdir for files containing SSN patterns..."
found_match=0

# Iterate over files ending in .txt or .csv under the rootdir
while IFS= read -r file; do
    if grep -Eq "$ssn_pattern" "$file"; then
        echo "SSN pattern found in file: $file"
        grep -EHn "$ssn_pattern" "$file"
        found_match=1
        # Pause to let the user review the match before continuing.
        read -p "Press ENTER to continue scanning..."
    fi
done < <(find "$rootdir" -type f \( -iname "*.txt" -o -iname "*.csv" \) 2>/dev/null)

if [ $found_match -eq 0 ]; then
    echo "No SSN patterns found in $rootdir."
else
    echo "Finished scanning. Please review the above matches."
fi
