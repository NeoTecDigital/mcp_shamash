#!/bin/sh
set -euo pipefail

# Source utilities
. /usr/local/bin/scanner-utils.sh

# Validate environment
if [ -z "${SHAMASH_TARGET_PATH:-}" ]; then
    echo "ERROR: SHAMASH_TARGET_PATH not provided" >&2
    exit 1
fi

# Check limits
check_limits

# Log operation start
log_scan "semgrep" "$SHAMASH_TARGET_PATH"

echo "Starting Semgrep SAST scan..."
echo "Target: $SHAMASH_TARGET_PATH"
echo "Config: ${SHAMASH_SEMGREP_CONFIG:-auto}"

# Build semgrep command
SEMGREP_CMD="semgrep"
SEMGREP_CMD="$SEMGREP_CMD --config=${SHAMASH_SEMGREP_CONFIG:-auto}"
SEMGREP_CMD="$SEMGREP_CMD --json"
SEMGREP_CMD="$SEMGREP_CMD --timeout=$SEMGREP_TIMEOUT"
SEMGREP_CMD="$SEMGREP_CMD --max-memory=$SEMGREP_MAX_MEMORY"
SEMGREP_CMD="$SEMGREP_CMD --no-git-ignore"  # Scan everything in scope
SEMGREP_CMD="$SEMGREP_CMD --disable-version-check"
SEMGREP_CMD="$SEMGREP_CMD --metrics=off"

# Add exclude patterns if provided
if [ -n "${SHAMASH_EXCLUDE_PATTERNS:-}" ]; then
    for pattern in $SHAMASH_EXCLUDE_PATTERNS; do
        SEMGREP_CMD="$SEMGREP_CMD --exclude='$pattern'"
    done
fi

# Output file
OUTPUT_FILE="/var/scanner/semgrep-results.json"

# Run semgrep with timeout enforcement
echo "Executing: $SEMGREP_CMD $SHAMASH_TARGET_PATH"

# Start semgrep in background
eval "$SEMGREP_CMD '$SHAMASH_TARGET_PATH'" > "$OUTPUT_FILE" 2>/tmp/scanner/semgrep.log &
SEMGREP_PID=$!

# Enforce timeout
enforce_timeout $SEMGREP_PID

# Check results
if [ $? -eq 0 ]; then
    echo "Semgrep scan completed successfully"
    if [ -f "$OUTPUT_FILE" ]; then
        echo "Results written to: $OUTPUT_FILE"
        # Show summary
        jq -r '. | length as $total | "Found \($total) findings"' "$OUTPUT_FILE" 2>/dev/null || echo "Results file exists"
    fi
else
    echo "Semgrep scan failed or timed out" >&2
    if [ -f /tmp/scanner/semgrep.log ]; then
        echo "Error log:" >&2
        cat /tmp/scanner/semgrep.log >&2
    fi
    exit 1
fi

# Log completion
log_scan "semgrep_complete" "$SHAMASH_TARGET_PATH"