#!/bin/bash


# initialisasi var
export DEBIAN_FRONTEND=noninteractive
OS=`uname -m`;
#MYIP=$(wget -qO- ipv4.icanhazip.com);

# get the VPS IP
#ip=`ifconfig venet0:0 | grep 'inet addr' | awk {'print $2'} | sed s/.*://`
MYIP=$(ifconfig | grep 'inet addr:' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | cut -d: -f2 | awk '{ print $1}' | head -1)
if [ "$MYIP" = "" ]; then
	MYIP=$(wget -qO- ipv4.icanhazip.com)
fi
MYIP2="s/xxxxxxxxx/$MYIP/g";
ether=`ifconfig | cut -c 1-8 | sort | uniq -u | grep venet0 | grep -v venet0:`
if [[ $ether = "" ]]; then
        ether=eth0
fi

#vps="zvur";
vps="aneka";

#if [[ $vps = "zvur" ]]; then
	#source="http://"
#else
	source="https://raw.githubusercontent.com/elangoverdosis2/cinta"
#fi

# go to root
cd


# install openvpn
apt-get install openvpn -y
wget -O /etc/openvpn/openvpn.tar $source/debian7/openvpn.tar
cd /etc/openvpn/
tar xf openvpn.tar
wget -O /etc/openvpn/1194.conf $source/debian7/1194.conf
service openvpn restart
sysctl -w net.ipv4.ip_forward=1
sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/g' /etc/sysctl.conf
wget -O /etc/iptables.up.rules $source/debian7/iptables.up.rules
sed -i '$ i\iptables-restore < /etc/iptables.up.rules' /etc/rc.local
MYIP=`ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0' | grep -v '192.168'`;
myip2="s/xxxxxxxxx/$MYIP/g";
sed -i 's/port 1194/port 55/g' /etc/openvpn/1194.conf
sed -i $myip2 /etc/iptables.up.rules;
iptables-restore < /etc/iptables.up.rules
service openvpn restart

# configure openvpn client config
cd /etc/openvpn/
wget -O /etc/openvpn/client.ovpn $source/debian7/1194-client.conf

cp /etc/openvpn/client.ovpn /home/vps/public_html/client.ovpn
sed -i $myip2 /home/vps/public_html/client.ovpn
sed -i "s/ports/55/" /home/vps/public_html/client.ovpn
rm -f /root/IP
