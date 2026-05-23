#!/bin/sh
# SECURITY: Hardening script for Tor Marketplace
# Run this as root before starting the service
# FIXED: Uses atomic rule application - no flush mid-script
set -euo pipefail

echo "[*] Applying kernel hardening..."

# Disable ICMP redirects
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.all.send_redirects=0
sysctl -w net.ipv6.conf.all.accept_redirects=0

# Disable source routing
sysctl -w net.ipv4.conf.all.accept_source_route=0
sysctl -w net.ipv6.conf.all.accept_source_route=0

# Disable timestamps
sysctl -w net.ipv4.tcp_timestamps=0

# Enable reverse path filtering
sysctl -w net.ipv4.conf.all.rp_filter=1

# Disable IPv6 entirely
sysctl -w net.ipv6.conf.all.disable_ipv6=1
sysctl -w net.ipv6.conf.default.disable_ipv6=1

# Restrict kernel logs
sysctl -w kernel.dmesg_restrict=1
sysctl -w kernel.kptr_restrict=2

# Increase entropy pool size
sysctl -w kernel.random.read_wakeup_threshold=64
sysctl -w kernel.random.write_wakeup_threshold=128

echo "[*] Applying iptables rules atomically..."

# SECURITY: Create a complete rule set, then apply atomically
# This prevents the system from being left without firewall if script fails

# Create temporary rule file
RULES_FILE=$(mktemp)
BACKUP_RULES_FILE=$(mktemp)

# Capture existing rules as backup (in case we need to rollback)
iptables-save > "$BACKUP_RULES_FILE" 2>/dev/null || true

cat > "$RULES_FILE" << 'EOF'
# Generated iptables rules - Tor Marketplace
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]

# Allow loopback
-A INPUT -i lo -j ACCEPT
-A OUTPUT -o lo -j ACCEPT

# Allow established connections
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow outgoing Tor connections (ORPort, DirPort)
-A OUTPUT -p tcp --dport 9001 -j ACCEPT
-A OUTPUT -p tcp --dport 9030 -j ACCEPT

# Allow DNS over Tor
-A OUTPUT -p udp --dport 53 -j ACCEPT

# Allow local service port
-A INPUT -p tcp --dport 9080 -j ACCEPT

# Log dropped packets (for debugging, remove in production for performance)
-A INPUT -j LOG --log-prefix "IPT_DROP: "
-A OUTPUT -j LOG --log-prefix "IPT_DROP: "

# Reject everything else
-A OUTPUT -j REJECT
-A INPUT -j REJECT
COMMIT
EOF

# Atomically apply new rules
if iptables-restore < "$RULES_FILE"; then
    echo "[*] iptables rules applied successfully"
    rm -f "$RULES_FILE" "$BACKUP_RULES_FILE"
else
    echo "[!] Failed to apply rules, rolling back to previous state"
    iptables-restore < "$BACKUP_RULES_FILE" 2>/dev/null || true
    rm -f "$RULES_FILE" "$BACKUP_RULES_FILE"
    exit 1
fi

echo "[*] Creating restricted user..."
id marketplace 2>/dev/null || useradd -r -s /bin/false -d /app marketplace

echo "[*] Setting file permissions..."
chown -R marketplace:marketplace /app 2>/dev/null || true
chmod 700 /app/data 2>/dev/null || true
chmod 600 /app/config.toml 2>/dev/null || true

echo "[*] Disabling swap..."
swapoff -a 2>/dev/null || true

echo "[*] Hardening complete."
echo "[*] Verify rules: iptables -L -n"
echo "[*] Start the marketplace with: docker-compose up -d"