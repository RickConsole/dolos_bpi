#!/bin/bash

# --- Configuration ---
# Management interface for BPI-R3's own internet and Dolos Web UI
MGMT_IF="wan"

# MitM Bridge: Connects 802.1x switch and trusted supplicant
MITM_SWITCH_IF="lan0"       # Connects to 802.1x port
MITM_SUPPLICANT_IF="lan1"   # Connects to trusted device
MITM_BRIDGE="dolos_bridge"

# Attacker Network Bridge: For operator machines
ATTACKER_IF1="lan2"
ATTACKER_IF2="lan3"
ATTACKER_BRIDGE="attk_br" # Renamed: Interface names must be <= 15 chars
ATTACKER_BRIDGE_IP="172.16.100.1"
ATTACKER_BRIDGE_NETMASK_CIDR="24" # Just the CIDR number
ATTACKER_DHCP_RANGE_START="172.16.100.100"
ATTACKER_DHCP_RANGE_END="172.16.100.200"
ATTACKER_DHCP_LEASE_TIME="12h"

# Path to the main Node.js Dolos script
# Assuming the adapted Node.js script will be named dolos_adapted.js or similar,
# and it's in the same directory as this script.
DOLOS_NODE_SCRIPT="./dolos.js" # This will likely need to be changed/adapted

# --- Helper Functions ---
log() {
    echo "[INFO] $1"
}

run_cmd() {
    log "Executing: $@"
    "$@"
    local status=$?
    if [ $status -ne 0 ]; then
        echo "[ERROR] Command failed: $@" >&2
    fi
    return $status
}

# --- Cleanup Function ---
CLEANUP_LOCK_FILE="/tmp/dolos_cleanup.lock"
cleanup() {
    # Simple lock mechanism to prevent multiple runs
    if [ -e "$CLEANUP_LOCK_FILE" ]; then
        log "Cleanup already in progress or completed."
        return
    fi
    touch "$CLEANUP_LOCK_FILE"

    log "Initiating cleanup..."

    log "Stopping Node.js Dolos script (if PID known)..."
    if [ -n "$DOLOS_PID" ] && ps -p "$DOLOS_PID" > /dev/null; then
        kill "$DOLOS_PID"
        wait "$DOLOS_PID" 2>/dev/null
    fi

    log "Stopping DHCP server..."
    pkill dnsmasq

    log "Disabling IP forwarding..."
    run_cmd sysctl -w net.ipv4.ip_forward=0

    log "Dismantling Attacker Bridge: $ATTACKER_BRIDGE"
    run_cmd ip link set "$ATTACKER_IF1" nomaster 2>/dev/null || true
    run_cmd ip link set "$ATTACKER_IF2" nomaster 2>/dev/null || true
    run_cmd ip link set "$ATTACKER_BRIDGE" down 2>/dev/null || true
    run_cmd ip link delete "$ATTACKER_BRIDGE" type bridge 2>/dev/null || true # Use type bridge for deletion

    log "Dismantling MitM Bridge: $MITM_BRIDGE"
    run_cmd ip link set "$MITM_SWITCH_IF" nomaster 2>/dev/null || true
    run_cmd ip link set "$MITM_SUPPLICANT_IF" nomaster 2>/dev/null || true
    run_cmd ip link set "$MITM_BRIDGE" down 2>/dev/null || true
    run_cmd ip link delete "$MITM_BRIDGE" type bridge 2>/dev/null || true # Use type bridge for deletion

    # Optional: Restore interfaces to lanbr0 if that's the default
    # log "Attempting to restore lan0-lan3 to lanbr0..."
    # for iface in "$MITM_SWITCH_IF" "$MITM_SUPPLICANT_IF" "$ATTACKER_IF1" "$ATTACKER_IF2"; do
    #   if ip link show lanbr0 &>/dev/null; then
    #     run_cmd ip link set "$iface" master lanbr0 2>/dev/null || true
    #   fi
    #   run_cmd ip link set "$iface" up 2>/dev/null || true
    # done
    # if ip link show lanbr0 &>/dev/null; then
    #    run_cmd ip link set lanbr0 up 2>/dev/null || true
    # fi

    rm -f "$CLEANUP_LOCK_FILE" # Remove lock file
    log "Cleanup complete."
    exit 0
}

# Trap signals for cleanup
trap cleanup SIGINT SIGTERM EXIT

# --- Main Setup ---
log "Starting Dolos BPI-R3 Environment Setup..."

log "Isolating LAN interfaces..."
for iface in "$MITM_SWITCH_IF" "$MITM_SUPPLICANT_IF" "$ATTACKER_IF1" "$ATTACKER_IF2"; do
    run_cmd ip link set "$iface" nomaster 2>/dev/null || true
    run_cmd ip link set "$iface" down 2>/dev/null || true # Ensure they are down before adding to new bridge
done

log "Creating MitM Bridge: $MITM_BRIDGE"
run_cmd ip link add name "$MITM_BRIDGE" type bridge
run_cmd ip link set "$MITM_BRIDGE" up
run_cmd ip link set "$MITM_SWITCH_IF" master "$MITM_BRIDGE"
run_cmd ip link set "$MITM_SUPPLICANT_IF" master "$MITM_BRIDGE"
run_cmd ip link set "$MITM_SWITCH_IF" up
run_cmd ip link set "$MITM_SUPPLICANT_IF" up
# Set promiscuous mode for interfaces on MitM bridge
run_cmd ip link set dev "$MITM_SWITCH_IF" promisc on
run_cmd ip link set dev "$MITM_SUPPLICANT_IF" promisc on
run_cmd ip link set dev "$MITM_BRIDGE" promisc on


log "Creating Attacker Network Bridge: $ATTACKER_BRIDGE"
run_cmd ip link add name "$ATTACKER_BRIDGE" type bridge
run_cmd ip link set "$ATTACKER_BRIDGE" up
run_cmd ip link set "$ATTACKER_IF1" master "$ATTACKER_BRIDGE"
run_cmd ip link set "$ATTACKER_IF2" master "$ATTACKER_BRIDGE"
run_cmd ip link set "$ATTACKER_IF1" up
run_cmd ip link set "$ATTACKER_IF2" up
run_cmd ip addr add "${ATTACKER_BRIDGE_IP}/${ATTACKER_BRIDGE_NETMASK_CIDR}" dev "$ATTACKER_BRIDGE"

log "Starting DHCP server on $ATTACKER_BRIDGE..."
# Ensure dnsmasq doesn't fail if the interface isn't ready immediately
sleep 1 
run_cmd dnsmasq --interface="$ATTACKER_BRIDGE" \
                --bind-interfaces \
                --dhcp-range="${ATTACKER_DHCP_RANGE_START},${ATTACKER_DHCP_RANGE_END},${ATTACKER_DHCP_LEASE_TIME}" \
                --dhcp-option=option:router,"${ATTACKER_BRIDGE_IP}" \
                --dhcp-option=option:dns-server,"${ATTACKER_BRIDGE_IP}" `# Optionally serve DNS if dnsmasq is also a resolver` \
                --no-resolv \
                --no-hosts \
                --listen-address="${ATTACKER_BRIDGE_IP}" \
                --log-dhcp # For debugging

log "Enabling IP forwarding..."
run_cmd sysctl -w net.ipv4.ip_forward=1

log "Launching Node.js Dolos script..."
# Construct arguments for the Node.js script
NODE_ARGS="--mgmt_if=${MGMT_IF}"
NODE_ARGS="${NODE_ARGS} --mitm_bridge=${MITM_BRIDGE}"
NODE_ARGS="${NODE_ARGS} --mitm_switch_if=${MITM_SWITCH_IF}"
NODE_ARGS="${NODE_ARGS} --mitm_supplicant_if=${MITM_SUPPLICANT_IF}"
NODE_ARGS="${NODE_ARGS} --attacker_bridge_subnet=${ATTACKER_BRIDGE_IP%.*}.0/${ATTACKER_BRIDGE_NETMASK_CIDR}" # e.g. 172.16.100.0/24
# Add other potential args needed by dolos.js/bridge_controller_adapted.js
# NODE_ARGS="${NODE_ARGS} --use_network_manager=false" # Example if needed

# This assumes your main dolos.js can parse these arguments
# And that the bridge_controller_adapted logic is called from there.
# We will need to adapt the Node.js side to accept these.
( cd "$(dirname "$0")" && node "$DOLOS_NODE_SCRIPT" $NODE_ARGS ) & # Run in background
DOLOS_PID=$!
log "Node.js script launched with PID $DOLOS_PID: node $DOLOS_NODE_SCRIPT $NODE_ARGS"
# log "ATTENTION: Node.js script launch is currently commented out. Please adapt dolos.js first." # Commented out this line
echo "Dolos is running. Press Ctrl+C to stop and cleanup."

# Keep script running until Ctrl+C
while true; do
    sleep 1
done
