#!/bin/bash
# WireGuard Setup Helper
umask 077
mkdir -p /etc/wireguard

if [ -f "/etc/wireguard/wg0.conf" ]; then
    echo "Config exists."
    exit 0
fi

echo "Generating Keys..."
wg genkey | tee /etc/wireguard/private.key | wg pubkey > /etc/wireguard/public.key
PRIV=$(cat /etc/wireguard/private.key)

echo "Creating Config..."
cat > /etc/wireguard/wg0.conf <<EOF
[Interface]
Address = 10.66.66.1/24
SaveConfig = true
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o wlan0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o wlan0 -j MASQUERADE
ListenPort = 51820
PrivateKey = $PRIV
EOF

echo "Enabling Forwarding..."
sysctl -w net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-wireguard.conf

echo "Done."
