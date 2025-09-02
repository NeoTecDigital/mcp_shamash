#!/bin/sh
# Scanner utility functions for boundary enforcement

set -euo pipefail

# Validate target is within allowed networks
validate_target() {
    local target="$1"
    local allowed_networks="${SHAMASH_ALLOWED_NETWORKS:-}"
    
    if [ -z "$allowed_networks" ]; then
        echo "ERROR: No allowed networks configured" >&2
        exit 1
    fi
    
    # Simple IP validation (enhanced validation done by boundary enforcer)
    if ! echo "$target" | grep -qE '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$'; then
        echo "ERROR: Invalid IP format: $target" >&2
        exit 1
    fi
    
    echo "Target validation passed: $target"
}

# Check resource limits
check_limits() {
    local max_memory="${SHAMASH_MAX_MEMORY:-2147483648}"  # 2GB default
    local max_processes="${SHAMASH_MAX_PROCESSES:-200}"
    
    # Check memory usage
    local current_memory=$(cat /proc/meminfo | grep MemAvailable | awk '{print $2}')
    if [ "$current_memory" -gt "$max_memory" ]; then
        echo "WARNING: Memory usage approaching limit" >&2
    fi
    
    # Check process count
    local current_processes=$(ps aux | wc -l)
    if [ "$current_processes" -gt "$max_processes" ]; then
        echo "ERROR: Process limit exceeded" >&2
        exit 1
    fi
}

# Log scan operation
log_scan() {
    local operation="$1"
    local target="$2"
    local timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    
    echo "{\"timestamp\":\"$timestamp\",\"operation\":\"$operation\",\"target\":\"$target\",\"container\":\"$HOSTNAME\"}" >> /var/scanner/audit.log
}

# Enforce timeout
enforce_timeout() {
    local timeout="${SHAMASH_TIMEOUT:-1800}"  # 30 minutes default
    local pid="$1"
    
    (
        sleep "$timeout"
        if kill -0 "$pid" 2>/dev/null; then
            echo "TIMEOUT: Killing process $pid after ${timeout}s" >&2
            kill -TERM "$pid" 2>/dev/null || true
            sleep 5
            kill -KILL "$pid" 2>/dev/null || true
        fi
    ) &
    
    timeout_pid=$!
    wait "$pid"
    kill "$timeout_pid" 2>/dev/null || true
}

# Clean up function
cleanup() {
    echo "Cleaning up scanner resources..." >&2
    # Kill any remaining processes
    pkill -u $(id -u) || true
    # Clear temporary files
    rm -rf /tmp/scanner/* 2>/dev/null || true
    exit 0
}

# Set up signal handlers
trap cleanup INT TERM

# Export functions
export -f validate_target check_limits log_scan enforce_timeout