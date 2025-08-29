#!/usr/bin/env bash
set -euo pipefail

read -rp "VPN pre-shared key (PSK): " VPN_PSK
read -rp "Optional domain (leave empty to use server IP): " VPN_DOMAIN

PUB_IP="$(curl -fsS ifconfig.me || dig +short myip.opendns.com @resolver1.opendns.com || hostname -I | awk '{print $1}')"
WAN_IF="$(ip route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')"
[[ -n "${WAN_IF}" ]] || { echo "[-] Could not detect WAN interface"; exit 1; }

# Force identifier
ID_VALUE="aminbaba"
POOL_SUBNET="10.30.30.0/24"
DNS1="1.1.1.1"
DNS2="8.8.8.8"

echo "[+] Installing strongSwan..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y strongswan iptables-persistent

echo "[+] Enable IPv4 forwarding..."
sysctl -w net.ipv4.ip_forward=1 >/dev/null
mkdir -p /etc/sysctl.d
printf "net.ipv4.ip_forward=1\n" >/etc/sysctl.d/99-ikev2-forward.conf
sysctl --system >/dev/null

echo "[+] Writing /etc/ipsec.conf ..."
cat >/etc/ipsec.conf <<CONF
config setup
  uniqueids=never
  charondebug="ike 1, knl 1, cfg 0"

conn ikev2-psk
  auto=add
  keyexchange=ikev2
  ike=aes256-sha2_256-modp2048,aes128-sha1-modp1024!
  esp=aes256-sha2_256,aes128-sha1!
  fragmentation=yes
  rekey=no
  dpdaction=clear
  dpddelay=30s

  left=%any
  leftid=@${ID_VALUE}
  leftsubnet=0.0.0.0/0
  leftauth=psk

  right=%any
  rightid=%any
  rightsourceip=${POOL_SUBNET}
  rightdns=${DNS1},${DNS2}
  rightauth=psk
CONF

echo "[+] Writing /etc/ipsec.secrets ..."
cat >/etc/ipsec.secrets <<SECRETS
: PSK "${VPN_PSK}"
SECRETS
chmod 600 /etc/ipsec.secrets

echo "[+] Firewall + NAT..."
iptables -A INPUT -p udp --dport 500 -j ACCEPT
iptables -A INPUT -p udp --dport 4500 -j ACCEPT
iptables -A FORWARD -s ${POOL_SUBNET} -j ACCEPT
iptables -A FORWARD -d ${POOL_SUBNET} -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -t nat -A POSTROUTING -s ${POOL_SUBNET} -o ${WAN_IF} -j MASQUERADE
netfilter-persistent save

echo "[+] Starting strongSwan..."
systemctl enable strongswan-starter
systemctl restart strongswan-starter

echo
echo "[✓] IKEv2 PSK server ready."
echo "Server address: ${VPN_DOMAIN:-$PUB_IP}"
echo "Identifier (leftid): aminbaba"
echo "Pre-Shared Key: ${VPN_PSK}"
echo
echo "Android config:"
echo "  Name: anything"
echo "  Type: IKEv2/IPSec PSK"
echo "  Server address: ${VPN_DOMAIN:-$PUB_IP}"
echo "  IPSec identifier: aminbaba"
echo "  IPSec pre-shared key: ${VPN_PSK}"
EOF
