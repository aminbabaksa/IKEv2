bash -c 'cat >/root/install_ikev2_eap.sh << "EOF"
#!/usr/bin/env bash
set -euo pipefail

# -------- Prompts --------
read -rp "VPN username: " VPN_USER
read -rsp "VPN password: " VPN_PASS; echo
read -rp "Optional domain (leave empty to use server IP): " VPN_DOMAIN

# -------- Detect basics --------
PUB_IP="$(curl -fsS ifconfig.me || dig +short myip.opendns.com @resolver1.opendns.com || hostname -I | awk "{print \$1}")"
WAN_IF="$(ip route get 1.1.1.1 | awk '\''{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}'\'')"
[[ -n "${WAN_IF}" ]] || { echo "[-] Could not detect WAN interface"; exit 1; }

ID_VALUE="${VPN_DOMAIN:-$PUB_IP}"       # used in certificate SAN and leftid
POOL_SUBNET="10.10.10.0/24"             # client address pool
DNS1="1.1.1.1"
DNS2="8.8.8.8"

echo "[+] Updating and installing packages..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y strongswan strongswan-pki iptables-persistent openssl

echo "[+] Enable IPv4 forwarding..."
sysctl -w net.ipv4.ip_forward=1 >/dev/null
mkdir -p /etc/sysctl.d
cat >/etc/sysctl.d/99-ikev2-forward.conf <<SYS
net.ipv4.ip_forward=1
SYS
sysctl --system >/dev/null

echo "[+] Create directories for certs..."
install -d -m 700 /etc/ipsec.d/private
install -d -m 755 /etc/ipsec.d/certs

echo "[+] Generating self-signed ECDSA server certificate (OK for Android \"Don\\'t verify server\")..."
# Key
openssl ecparam -genkey -name prime256v1 -out /etc/ipsec.d/private/serverkey.pem
chmod 600 /etc/ipsec.d/private/serverkey.pem

# Self-signed cert with SAN = domain/IP
SAN_IP=""
SAN_DNS=""
if [[ "${ID_VALUE}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  SAN_IP="IP:${ID_VALUE}"
else
  SAN_DNS="DNS:${ID_VALUE}"
fi

openssl req -new -key /etc/ipsec.d/private/serverkey.pem -subj "/CN=${ID_VALUE}" -out /tmp/server.csr
openssl x509 -req -in /tmp/server.csr -signkey /etc/ipsec.d/private/serverkey.pem -days 3650 \
  -extfile <(printf "subjectAltName=%s%s%s\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n" \
                   "${SAN_IP}" "${SAN_IP:+,}" "${SAN_DNS}") \
  -out /etc/ipsec.d/certs/servercert.pem
rm -f /tmp/server.csr

echo "[+] Writing /etc/ipsec.conf ..."
cat >/etc/ipsec.conf <<CONF
# strongSwan IKEv2 EAP-MSCHAPv2 (Android + Windows)
config setup
  uniqueids=never
  charondebug="ike 1, knl 1, cfg 0"

conn ikev2-eap
  auto=add
  keyexchange=ikev2
  ike=aes256-sha2_256-modp2048,aes256-sha2_256-modp1536,aes128-sha1-modp1024!
  esp=aes256-sha2_256,aes128-sha1!
  fragmentation=yes
  rekey=no
  dpdaction=clear
  dpddelay=30s
  compress=no

  left=%any
  leftid=@${ID_VALUE}
  leftauth=pubkey
  leftcert=servercert.pem
  leftsendcert=always
  leftsubnet=0.0.0.0/0

  right=%any
  rightauth=eap-mschapv2
  eap_identity=%identity
  rightsourceip=${POOL_SUBNET}
  rightdns=${DNS1},${DNS2}
CONF

echo "[+] Writing /etc/ipsec.secrets ..."
cat >/etc/ipsec.secrets <<SECRETS
: RSA serverkey.pem
${VPN_USER} : EAP "${VPN_PASS}"
SECRETS
chmod 600 /etc/ipsec.secrets

echo "[+] Opening firewall (UDP/500, UDP/4500) and enabling NAT..."
iptables -A INPUT -p udp --dport 500 -j ACCEPT
iptables -A INPUT -p udp --dport 4500 -j ACCEPT
iptables -A FORWARD -s ${POOL_SUBNET} -j ACCEPT
iptables -A FORWARD -d ${POOL_SUBNET} -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -t nat -A POSTROUTING -s ${POOL_SUBNET} -o ${WAN_IF} -j MASQUERADE
netfilter-persistent save

echo "[+] Enabling and restarting strongSwan..."
systemctl enable strongswan-starter
systemctl restart strongswan-starter

echo
echo "[✓] IKEv2 EAP server ready."
echo "    Server address:    ${VPN_DOMAIN:-$PUB_IP}"
echo "    Identity/ID:       (leave empty on Android OR set to ${VPN_USER})"
echo "    Username:          ${VPN_USER}"
echo "    Password:          (hidden)"
echo
echo "Android setup (matches your screenshot):"
echo "  Type: IKEv2/IPSec MSCHAPv2"
echo "  Server address: ${VPN_DOMAIN:-$PUB_IP}"
echo "  IPSec identifier: Not used"
echo "  IPSec CA certificate: Don\\'t verify server"
echo "  Username: ${VPN_USER}"
echo "  Password: (the one you set)"
echo
echo "Tips:"
echo " - If you later add a domain, re-run and enter it so SAN matches."
echo " - Ensure UDP 500/4500 are allowed by your provider."
EOF
chmod +x /root/install_ikev2_eap.sh
bash /root/install_ikev2_eap.sh'
