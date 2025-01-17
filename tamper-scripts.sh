#!/bin/bash

# Define the directory where SQLmap tamper scripts are stored
tamper_dir="/usr/share/sqlmap/tamper/"

# Output directory for results
output_dir="./sqlmap_results"
skipped_log="./sqlmap_results/skipped_scripts.log"
mkdir -p "$output_dir"

# Check if a target URL is provided
# if [ -z "$1" ]; then
# 	echo "Usage: $0 <target_url>"
# 	exit 1
# fi

# Target URL and parameters
url="$1"
data='{"id":1}'
headers="Content-Type: application/json"

output_file=""

# Function to handle Ctrl+C
trap "echo 'Scan interrupted by user. Cleaning up...'; if [ -n \"$output_file\" ]; then rm -f \"$output_file\"; fi; exit 1" SIGINT

# Function to check if the server is reachable
function check_server {
	for attempt in {1..3}; do
		response=$(curl -o /dev/null -s -w "%{http_code}" "$url")
		if [[ "$response" -ge 200 && "$response" -lt 500 ]]; then
			echo "Successfully connected to $url (HTTP status $response)."
			return 0
		fi
		echo "Attempt $attempt: Server at $url is unreachable (HTTP status $response). Retrying..."
		sleep 2
	done
	echo "Server at $url is unreachable after 3 attempts. Exiting..."
	exit 1
}

# Function to process a single tamper script
function process_tamper_script {
	script="$1"
	original_name=$(basename "$script" .py)
	tamper_name=$(echo "$original_name" | sed 's/[^a-zA-Z0-9_-]/_/g')

	# Log original and sanitized names
	echo "Original name: $original_name, Sanitized name: $tamper_name" | tee -a "$skipped_log"

	# Define the output file
	output_file="${output_dir}/${tamper_name}_results.txt"

	# Skip if results for this tamper script already exist
	if [ -f "$output_file" ]; then
		echo "Skipping $tamper_name (already tested)." | tee -a "$skipped_log"
		return
	fi

	echo "Starting SQLmap with tamper script: $tamper_name at $(date '+Y-%m-%d %H:%M:%S')"

	# Check server connectivity before running SQLmap
	check_server

	# Run SQLmap and save output to file
	sqlmap -u "$url" \
		--data="$data" \
		--headers="$headers" \
		--tamper="$tamper_name" \
		--level=5 \
		--risk=3 \
		--batch \
		--output-dir="$output_dir" >> "$output_file" 2>&1
	
	# Check server connectivity after running SQLmap
	check_server

	# Check if vulnerabilities were detected
	search_string="injection"
	if grep -q "$search_string" "$output_file"; then
		echo "Tamper script $tamper_name successfully detected a vulnerability!" >> "$output_file"
	else
		echo "No vulnerability detected with tamper script $tamper_name." >> "$output_file"
	fi

	echo "Finished SQLmap with tamper script: $tamper_name at $(date '+%Y-%m-%d %H:%M:%S')"
	echo "Results stored in $output_file"
}

# Check server connectivity before starting the scan
check_server

# Iterate through each tamper script
find "$tamper_dir" -name "*.py" -type f -print0 | while IFS= read -r -d '' script; do
	process_tamper_script "$script"
done