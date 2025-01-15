#!/bin/bash

# Define the directory where SQLmap tamper scripts are stored
tamper_dir="/usr/share/sqlmap/tamper/"

# Output directory for results
output_dir="./sqlmap_results"
skipped_log="./sqlmap_results/skipped_scripts.log"
mkdir -p "$output_dir"

# Check if a target URL is provided
if [ -z "$1" ]; then
	echo "Usage: $0 <target_url>"
	exit 1
fi

# Target URL and parameters
url="$1"
data='{"id":1}'
headers="Content-Type: application/json"

# Function to handle Ctrl+C
trap "echo 'Scan interrupted by user. Cleaning up...'; rm -f \"$output_file\"; exit 1" SIGINT

# Iterate through each tamper script
for script in $(find "$tamper_dir" -name "*.py" -type f); do
	# Extract the script name without path and extension
	tamper_name=$(basename "$script" .py | sed 's/[^a-zA-Z0-9_-]/_/g')

	# Define the output file
	output_file="${output_dir}/${tamper_name}_results.txt"

	# Skip if results for this tamper script already exist
	if [ -f "$output_file" ]; then
		echo "Skipping $tamper_name (already tested)." | tee -a "$skipped_log"
		continue
	fi
	
	echo "Starting SQLmap with tamper script: $tamper_name at $(date '+%Y-%m-%d %H:%M:%S')"

	# Run SQLmap and save output to the file
	sqlmap -u "$url" \
		--data="$data" \
		--method=POST \
		--headers="$headers" \
		--level=5 \
		--risk=3 \
		--batch \
		--output-dir="$output_dir" >> "$output_file" 2>&1 

	# Check if vulnerabilities were detected
	if grep -q "the back-end DBMS is" "$output_file"; then
		echo "Tamper script $tamper_name successfully detected a vulnerability!" >> "$output_file"
	else
		echo "No vulnerability detected with tamper script $tamper_name." >> "$output_file"
	fi

	echo "Finished SQLmap with tamper script: $tamper_name at $(date '+%Y-%m-%d %H:%M:%S')" >> "$output_file"
	echo "Results stored in $output_file"
done