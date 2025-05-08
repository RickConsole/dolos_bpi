#!/bin/bash

# --- Configuration ---
# Management interface for BPI-R3's own internet and Dolos Web UI
MGMT_IF="enp1s0"

# MitM Bridge: Connects 802.1x switch and trusted supplicant
MITM_SWITCH_IF="enp2s0"       # Connects to 802.1x port
MITM_SUPPLICANT_IF="enp3s0"   # Connects to trusted device
MITM_BRIDGE="dolos_bridge"

# Attacker Network Interface: For operator machines
ATTACKER_IF1="enp4s0" # The single physical interface for attackers
# ATTACKER_IF2="lan3" # Potential second attacker adapter
ATTACKER_NET_IP="172.16.100.1" # IP for the attacker interface itself
ATTACKER_NET_CIDR="24"
ATTACKER_DHCP_RANGE_START="172.16.100.100"
ATTACKER_DHCP_RANGE_END="172.16.100.200"
ATTACKER_DHCP_LEASE_TIME="12h"

# Path to the main Node.js Dolos script,
DOLOS_NODE_SCRIPT="./dolos.js" # This will likely need to be changed/adapted

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
    # Check if lock file creation succeeded before proceeding
    if ! touch "$CLEANUP_LOCK_FILE" 2>/dev/null; then
        log "Failed to create cleanup lock file. Exiting cleanup."
        return 1
    fi


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

    log "Cleaning up Attacker Interface: $ATTACKER_IF1"
    if [ -n "$ATTACKER_IF1" ]; then
      # Remove IP address assigned
      run_cmd ip addr del "${ATTACKER_NET_IP}/${ATTACKER_NET_CIDR}" dev "$ATTACKER_IF1" 2>/dev/null || true
      # Optionally set interface down or back to default state if needed
      # run_cmd ip link set "$ATTACKER_IF1" down
    fi
    # No bridge to dismantle

    log "Dismantling MitM Bridge: $MITM_BRIDGE"
    if [ -n "$MITM_SWITCH_IF" ]; then
      run_cmd ip link set "$MITM_SWITCH_IF" nomaster 2>/dev/null || true
    fi
    if [ -n "$MITM_SUPPLICANT_IF" ]; then
      run_cmd ip link set "$MITM_SUPPLICANT_IF" nomaster 2>/dev/null || true
    fi
    run_cmd ip link set "$MITM_BRIDGE" down 2>/dev/null || true
    run_cmd ip link delete "$MITM_BRIDGE" type bridge 2>/dev/null || true # Use type bridge for deletion

    rm -f "$CLEANUP_LOCK_FILE" # Remove lock file
    log "Cleanup complete."
    exit 0
}

# Trap signals for cleanup
trap cleanup SIGINT SIGTERM EXIT

# --- Main Setup ---
log "Starting Dolos Environment Setup..." # Generic name

log "Isolating LAN interfaces..."
# Create a list of interfaces to isolate/configure, filtering out empty ones
interfaces_to_configure=()
[ -n "$MITM_SWITCH_IF" ] && interfaces_to_configure+=("$MITM_SWITCH_IF")
[ -n "$MITM_SUPPLICANT_IF" ] && interfaces_to_configure+=("$MITM_SUPPLICANT_IF")
[ -n "$ATTACKER_IF1" ] && interfaces_to_configure+=("$ATTACKER_IF1")
# ATTACKER_IF2 is removed

for iface in "${interfaces_to_configure[@]}"; do
    log "Preparing $iface..."
    run_cmd ip link set "$iface" nomaster 2>/dev/null || true
    run_cmd ip link set "$iface" down 2>/dev/null || true # Ensure they are down before adding to new bridge
done

log "Creating MitM Bridge: $MITM_BRIDGE"
run_cmd ip link add name "$MITM_BRIDGE" type bridge
run_cmd ip link set "$MITM_BRIDGE" up
if [ -n "$MITM_SWITCH_IF" ]; then
  run_cmd ip link set "$MITM_SWITCH_IF" master "$MITM_BRIDGE"
  run_cmd ip link set "$MITM_SWITCH_IF" up
  run_cmd ip link set dev "$MITM_SWITCH_IF" promisc on
fi
if [ -n "$MITM_SUPPLICANT_IF" ]; then
  run_cmd ip link set "$MITM_SUPPLICANT_IF" master "$MITM_BRIDGE"
  run_cmd ip link set "$MITM_SUPPLICANT_IF" up
  run_cmd ip link set dev "$MITM_SUPPLICANT_IF" promisc on
fi
run_cmd ip link set dev "$MITM_BRIDGE" promisc on


log "Configuring Attacker Network Interface: $ATTACKER_IF1"
if [ -n "$ATTACKER_IF1" ]; then
    # Assign IP directly to the physical interface
    run_cmd ip addr add "${ATTACKER_NET_IP}/${ATTACKER_NET_CIDR}" dev "$ATTACKER_IF1"
    # Ensure the interface is up
    run_cmd ip link set "$ATTACKER_IF1" up
else
    log "Attacker interface (ATTACKER_IF1) not defined. Skipping configuration."
fi


# Start DHCP server directly on the physical attacker interface
if [ -n "$ATTACKER_IF1" ]; then
    log "Starting DHCP server on $ATTACKER_IF1..."
    # Ensure dnsmasq doesn't fail if the interface isn't ready immediately
    sleep 1
    run_cmd dnsmasq --interface="$ATTACKER_IF1" \
                    --bind-interfaces \
                    --dhcp-range="${ATTACKER_DHCP_RANGE_START},${ATTACKER_DHCP_RANGE_END},${ATTACKER_DHCP_LEASE_TIME}" \
                    --dhcp-option=option:router,"${ATTACKER_NET_IP}" \
                    --dhcp-option=option:dns-server,"${ATTACKER_NET_IP}" `# Optionally serve DNS if dnsmasq is also a resolver` \
                    --no-resolv \
                    --no-hosts \
                    --listen-address="${ATTACKER_NET_IP}" \
                    --log-dhcp # For debugging
else
    log "Attacker interface (ATTACKER_IF1) not defined. Skipping DHCP server start."
fi
                --log-dhcp # For debugging

log "Enabling IP forwarding..."
run_cmd sysctl -w net.ipv4.ip_forward=1

log "Launching Node.js Dolos script..."
# Construct arguments for the Node.js script
NODE_ARGS="--mgmt_if=${MGMT_IF}"
NODE_ARGS="${NODE_ARGS} --mitm_bridge=${MITM_BRIDGE}"
NODE_ARGS="${NODE_ARGS} --mitm_switch_if=${MITM_SWITCH_IF}"
NODE_ARGS="${NODE_ARGS} --mitm_supplicant_if=${MITM_SUPPLICANT_IF}"
NODE_ARGS="${NODE_ARGS} --attacker_if=${ATTACKER_IF1}" # Pass the physical attacker interface name
NODE_ARGS="${NODE_ARGS} --attacker_subnet=${ATTACKER_NET_IP%.*}.0/${ATTACKER_NET_CIDR}" # Pass the subnet defined on the physical interface
# NODE_ARGS="${NODE_ARGS} --attacker_bridge=${ATTACKER_BRIDGE}" # Removed - No attacker bridge
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
