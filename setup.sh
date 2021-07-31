#!/bin/bash

# For Ubuntu 20.04 / 18.04
export DONE=false

export isroot=$(id -u)
if [ $isroot -ne 0 ]
  then
  echo -e "-----------------------------------------------------"
  else
  echo -e "Must be a non-root user! Create or login as user\n\033[31mexiting...\033[0m"
  exit
fi

echo -e "\n\t\t\033[33mIKEv2 \033[35mVPN Server \033[0minstallation has started"

echo -e "\n \033[32m* \033[0m Updating packages"
sudo apt update

echo -e "\n \033[32m* \033[0m Upgrading packages"
sudo apt upgrade

if [ -e /var/run/reboot-required.pkgs ]
then
echo -e "\n\nReboot required! Run script after rebooting system!"
exit
else
echo -e "\nUpgrading finished\n"
fi

echo -e "\n \033[32m* \033[0m Installing \033[35mStrongSwan\033[0m"
sudo apt install strongswan strongswan-pki libstrongswan-extra-plugins libcharon-extra-plugins

echo -e "\n \033[32m* \033[0m Creating \033[35mCA\033[0m files"

if [ -e ~/pki ]
then
echo -e "\nMake sure that there is no file or directory (~/pki) conflicting with strongswan\nexiting..."
exit
fi

mkdir -p ~/pki/{cacerts,certs,private}
chmod 700 ~/pki

ipsec pki --gen --type rsa --size 4096 --outform pem > ~/pki/private/ca-key.pem
ipsec pki --self --ca --lifetime 3650 --in ~/pki/private/ca-key.pem \
    --type rsa --dn "CN=VPN root CA" --outform pem > ~/pki/cacerts/ca-cert.pem

echo -e "\n \033[32m* \033[0m Creating \033[35mVPN Server Certificates\033[0m"
ipsec pki --gen --type rsa --size 4096 --outform pem > ~/pki/private/server-key.pem

export server=$(curl ipinfo.io/ip)

ipsec pki --pub --in ~/pki/private/server-key.pem --type rsa \
    | ipsec pki --issue --lifetime 1825 \
        --cacert ~/pki/cacerts/ca-cert.pem \
        --cakey ~/pki/private/ca-key.pem \
        --dn "CN=$server" --san "$server" \
            --flag serverAuth --flag ikeIntermediate --outform pem \
        >  ~/pki/certs/server-cert.pem

sudo cp -r ~/pki/* /etc/ipsec.d/

echo -e "\n \033[32m* \033[0m Configuring \033[35mStrongSwan\033[0m"

echo "- Backing up original conf"
if [ -e /etc/ipsec.conf.original ]
then
echo -e "- Backup file already exist"
else
sudo mv /etc/ipsec.conf{,.original}
fi

echo -e "\n*****\033[33m"
echo -e "config setup\n    charondebug=\"ike 1, knl 1, cfg 0\"\n    uniqueids=no\n\nconn ikev2-vpn\n    auto=add\n    compress=no\n    type=tunnel\n    keyexchange=ikev2\n    fragmentation=yes\n    forceencaps=yes\n    dpdaction=clear\n    dpddelay=300s\n    rekey=no\n    left=%any\n    leftid=$server\n    leftcert=server-cert.pem\n    leftsendcert=always\n    leftsubnet=0.0.0.0/0\n    right=%any\n    rightid=%any\n    rightauth=eap-mschapv2\n    rightsourceip=10.10.10.0/24\n    rightdns=8.8.8.8,8.8.4.4\n    rightsendcert=never\n    eap_identity=%identity" | sudo tee /etc/ipsec.conf
echo -e "\033[0m*****\n"

echo -e "\n \033[32m* \033[0m Configuring \033[35mAuthentication\033[0m"

echo -e "\n*****\033[33m"
echo -e ": RSA \"server-key.pem\"\n" | sudo tee -a /etc/ipsec.secrets
echo -e "\033[0m*****\n"

export username=""
export password=""

read -p "Username(Blank for: $USER): " username
read -p "Password(Blank for: random): " password

if [ "$username" == "" ]
then
username=$USER
fi

if [ "$password" == "" ]
then
wget -O pass 'http://www.random.org/integers/?num=1&min=1111&max=9999&col=1&base=10&format=plain&rnd=new'
password=$(cat pass)
sudo rm pass
fi

echo -e "\n*****\033[33m"
echo "$username : EAP \"$password\"" | sudo tee -a /etc/ipsec.secrets
echo -e "\033[0m*****\n"

# sudo systemctl restart strongswan

echo -e "\n \033[32m* \033[0m Configuring \033[35mFirewall\033[0m"

sudo ufw allow OpenSSH
sudo ufw enable

sudo ufw allow 500,4500/udp
ip route | grep default

echo "- Backing up original rules"
if [ -e /etc/ufw/before.rules.original ]
then
echo -e "- Backup file already exist"
else
sudo mv /etc/ufw/before.rules{,.original}
fi


rules="
#\n# rules.before\n#\n# Rules that should be run before the ufw command line added rules. Custom\n# rules should be added to one of these chains:\n#   ufw-before-input\n#   ufw-before-output\n#   ufw-before-forward\n#\n\n*nat\n-A POSTROUTING -s 10.10.10.0/24 -o eth0 -m policy --pol ipsec --dir out -j ACCEPT\n-A POSTROUTING -s 10.10.10.0/24 -o eth0 -j MASQUERADE\nCOMMIT\n\n*mangle\n-A FORWARD --match policy --pol ipsec --dir in -s 10.10.10.0/24 -o eth0 -p tcp -m tcp --tcp-flags SYN,RST SYN -m tcpmss --mss 1361:1536 -j TCPMSS --set-mss 1360\nCOMMIT\n\n# Don't delete these required lines, otherwise there will be errors\n*filter\n:ufw-before-input - [0:0]\n:ufw-before-output - [0:0]\n:ufw-before-forward - [0:0]\n:ufw-not-local - [0:0]\n# End required lines\n\n-A ufw-before-forward --match policy --pol ipsec --dir in --proto esp -s 10.10.10.0/24 -j ACCEPT\n-A ufw-before-forward --match policy --pol ipsec --dir out --proto esp -d 10.10.10.0/24 -j ACCEPT\n\n# allow all on loopback\n-A ufw-before-input -i lo -j ACCEPT\n-A ufw-before-output -o lo -j ACCEPT\n\n# quickly process packets for which we already have a connection\n-A ufw-before-input -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n-A ufw-before-output -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n-A ufw-before-forward -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n\n# drop INVALID packets (logs these in loglevel medium and higher)\n-A ufw-before-input -m conntrack --ctstate INVALID -j ufw-logging-deny\n-A ufw-before-input -m conntrack --ctstate INVALID -j DROP\n\n# ok icmp codes for INPUT\n-A ufw-before-input -p icmp --icmp-type destination-unreachable -j ACCEPT\n-A ufw-before-input -p icmp --icmp-type time-exceeded -j ACCEPT\n-A ufw-before-input -p icmp --icmp-type parameter-problem -j ACCEPT\n-A ufw-before-input -p icmp --icmp-type echo-request -j ACCEPT\n\n# ok icmp code for FORWARD\n-A ufw-before-forward -p icmp --icmp-type destination-unreachable -j ACCEPT\n-A ufw-before-forward -p icmp --icmp-type time-exceeded -j ACCEPT\n-A ufw-before-forward -p icmp --icmp-type parameter-problem -j ACCEPT\n-A ufw-before-forward -p icmp --icmp-type echo-request -j ACCEPT\n\n# allow dhcp client to work\n-A ufw-before-input -p udp --sport 67 --dport 68 -j ACCEPT\n\n#\n# ufw-not-local\n#\n-A ufw-before-input -j ufw-not-local\n\n# if LOCAL, RETURN\n-A ufw-not-local -m addrtype --dst-type LOCAL -j RETURN\n\n# if MULTICAST, RETURN\n-A ufw-not-local -m addrtype --dst-type MULTICAST -j RETURN\n\n# if BROADCAST, RETURN\n-A ufw-not-local -m addrtype --dst-type BROADCAST -j RETURN\n\n# all other non-local packets are dropped\n-A ufw-not-local -m limit --limit 3/min --limit-burst 10 -j ufw-logging-deny\n-A ufw-not-local -j DROP\n\n# allow MULTICAST mDNS for service discovery (be sure the MULTICAST line above\n# is uncommented)\n-A ufw-before-input -p udp -d 224.0.0.251 --dport 5353 -j ACCEPT\n\n# allow MULTICAST UPnP for service discovery (be sure the MULTICAST line above\n# is uncommented)\n-A ufw-before-input -p udp -d 239.255.255.250 --dport 1900 -j ACCEPT\n\n# don't delete the 'COMMIT' line or these rules won't be processed\nCOMMIT"

echo -e "\n*****\033[33m"
echo -e $rules | sudo tee /etc/ufw/before.rules
echo -e "\033[0m*****\n"

echo -e "\033[32m net/ipv4/ip_forward: \033[0m"
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward

# Do not accept ICMP redirects (prevent MITM attacks)
# Ensure the following line is set
echo -e "\033[32m net/ipv4/conf/all/accept_redirects: \033[0m"
echo 0 | sudo tee /proc/sys/net/ipv4/conf/all/accept_redirects

# Do not send ICMP redirects (we are not a router)
# Add the following lines
echo -e "\033[32m net/ipv4/conf/all/send_redirects: \033[0m"
echo 0 | sudo tee /proc/sys/net/ipv4/conf/all/send_redirects

echo -e "\033[32m net/ipv4/ip_no_pmtu_disc: \033[0m"
echo 1 | sudo tee /proc/sys/net/ipv4/ip_no_pmtu_disc

sudo ufw disable
sudo ufw enable

sudo ipsec restart

DONE=true

if $DONE
then
echo -e "\n\t\tCongratulations! The VPN Server Setup is completed!\nGet the CA from\t\033[44m/etc/ipsec.d/cacerts/ca-cert.pem\033[0m"
echo -e "Username $username\nPassword $password\n"
else
echo -e "\033[41mFAILED\033[0m\nTry again later"
fi

