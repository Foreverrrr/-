#!/bin/bash


# initialisasi var
export DEBIAN_FRONTEND=noninteractive
OS=`uname -m`;
#MYIP=$(wget -qO- ipv4.icanhazip.com);


#vps="zvur";
vps="aneka";

#if [[ $vps = "zvur" ]]; then
	#source="http://"
#else
	source="https://raw.githubusercontent.com/Foreverrrr/-/master"
#fi

# go to root
cd


# disable ipv6
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local
#sed -i 's/net.ipv6.conf.all.disable_ipv6 = 0/net.ipv6.conf.all.disable_ipv6 = 1/g' /etc/sysctl.conf
#sed -i 's/net.ipv6.conf.default.disable_ipv6 = 0/net.ipv6.conf.default.disable_ipv6 = 1/g' /etc/sysctl.conf
#sed -i 's/net.ipv6.conf.lo.disable_ipv6 = 0/net.ipv6.conf.lo.disable_ipv6 = 1/g' /etc/sysctl.conf
#sed -i 's/net.ipv6.conf.eth0.disable_ipv6 = 0/net.ipv6.conf.eth0.disable_ipv6 = 1/g' /etc/sysctl.conf
#sysctl -p

# install wget and curl
apt-get update;apt-get -y install wget curl;
apt-get install gem
# set time GMT +7
ln -fs /usr/share/zoneinfo/Asia/Kuala_Lumpur /etc/localtime

# set locale
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config
service ssh restart

# set repo
wget -O /etc/apt/sources.list $source/sources.list.debian7
wget http://www.dotdeb.org/dotdeb.gpg
wget http://www.webmin.com/jcameron-key.asc
cat dotdeb.gpg | apt-key add -;rm dotdeb.gpg
cat jcameron-key.asc | apt-key add -;rm jcameron-key.asc

# remove unused
apt-get -y --purge remove samba*;
apt-get -y --purge remove apache2*;
apt-get -y --purge remove sendmail*;
apt-get -y --purge remove bind9*;
apt-get -y --purge remove dropbear*;
#apt-get -y autoremove;

# update
apt-get update;apt-get -y upgrade;

# install webserver
apt-get -y install nginx php5-fpm php5-cli
apt-get -y install zip tar
apt-get install python
cd
# install essential package
#echo "mrtg mrtg/conf_mods boolean true" | debconf-set-selections
#apt-get -y install bmon iftop htop nmap axel nano iptables traceroute sysv-rc-conf dnsutils bc nethogs openvpn vnstat less screen psmisc apt-file whois ptunnel ngrep mtr git zsh mrtg snmp snmpd snmp-mibs-downloader unzip unrar rsyslog debsums rkhunter
apt-get -y install bmon iftop htop nmap axel nano iptables traceroute sysv-rc-conf dnsutils bc nethogs vnstat less screen psmisc apt-file whois ptunnel ngrep mtr git zsh unzip unrar rsyslog debsums rkhunter
apt-get -y install build-essential

# disable exim
service exim4 stop
sysv-rc-conf exim4 off

# update apt-file
apt-file update

# setting vnstat
vnstat -u -i $ether
service vnstat restart

#text gambar
apt-get install boxes


# text gambar
apt-get install boxes

# color text
cd
rm -rf /root/.bashrc
wget -O /root/.bashrc "https://raw.githubusercontent.com/fluxo7/m.e.n.u/master/method1/.bashrc"

# install lolcat
sudo apt-get -y install ruby
sudo gem install lolcat


# install webserver
cd
rm /etc/nginx/sites-enabled/default
rm /etc/nginx/sites-available/default
wget -O /etc/nginx/nginx.conf $source/nginx.conf
mkdir -p /home/vps/public_html
echo "<pre>Modified by elang overdosis n' yusuf ardiansyah</pre>" > /home/vps/public_html/index.html
echo "<?php phpinfo(); ?>" > /home/vps/public_html/info.php
wget -O /etc/nginx/conf.d/vps.conf $source/vps.conf
sed -i 's/listen = \/var\/run\/php5-fpm.sock/listen = 127.0.0.1:9000/g' /etc/php5/fpm/pool.d/www.conf
service php5-fpm restart
service nginx restart

#PASS=`cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 15 | head -n 1`;
#useradd -M -s /bin/false deenie11
#echo "Fluxo7:$PASS" | chpasswd
#echo "Fluxo7" >> pass.txt
#echo "$PASS" >> pass.txt
#cp pass.txt /home/vps/public_html/
#rm -f /root/pass.txt
cd

# install badvpn
#wget -O /usr/bin/badvpn-udpgw $source/badvpn-udpgw
#if [[ $OS == "x86_64" ]]; then
#wget -O /usr/bin/badvpn-udpgw $source/badvpn-udpgw64
#fi
#sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300' /etc/rc.local
#chmod +x /usr/bin/badvpn-udpgw
#screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300
cd

# install mrtg
#apt-get update;apt-get -y install snmpd;
#wget -O /etc/snmp/snmpd.conf $source/snmpd.conf
#wget -O /root/mrtg-mem.sh $source/mrtg-mem.sh
#chmod +x /root/mrtg-mem.sh
#cd /etc/snmp/
#sed -i 's/TRAPDRUN=no/TRAPDRUN=yes/g' /etc/default/snmpd
#service snmpd restart
#snmpwalk -v 1 -c public localhost 1.3.6.1.4.1.2021.10.1.3.1
#mkdir -p /home/vps/public_html/mrtg
#cfgmaker --zero-speed 100000000 --global 'WorkDir: /home/vps/public_html/mrtg' --output /etc/mrtg.cfg public@localhost
#curl $source/debian7/mrtg.conf >> /etc/mrtg.cfg
#sed -i 's/WorkDir: \/var\/www\/mrtg/# WorkDir: \/var\/www\/mrtg/g' /etc/mrtg.cfg
#sed -i 's/# Options\[_\]: growright, bits/Options\[_\]: growright/g' /etc/mrtg.cfg
#indexmaker --output=/home/vps/public_html/mrtg/index.html /etc/mrtg.cfg
#if [ -x /usr/bin/mrtg ] && [ -r /etc/mrtg.cfg ]; then mkdir -p /var/log/mrtg ; env LANG=C /usr/bin/mrtg /etc/mrtg.cfg 2>&1 | tee -a /var/log/mrtg/mrtg.log ; fi
#if [ -x /usr/bin/mrtg ] && [ -r /etc/mrtg.cfg ]; then mkdir -p /var/log/mrtg ; env LANG=C /usr/bin/mrtg /etc/mrtg.cfg 2>&1 | tee -a /var/log/mrtg/mrtg.log ; fi
#if [ -x /usr/bin/mrtg ] && [ -r /etc/mrtg.cfg ]; then mkdir -p /var/log/mrtg ; env LANG=C /usr/bin/mrtg /etc/mrtg.cfg 2>&1 | tee -a /var/log/mrtg/mrtg.log ; fi
cd

# setting port ssh
#sed -i 's/Port 22/Port 22/g' /etc/ssh/sshd_config
#sed -i '/Port 22/a Port 80' /etc/ssh/sshd_config
#sed -i '/Port 22/a Port 143' /etc/ssh/sshd_config
sed -i '/Port 22/a Port 143' /etc/ssh/sshd_config
sed -i 's/Port 22/Port  22/g' /etc/ssh/sshd_config
sed -i '$ i\Banner bannerssh' /etc/ssh/sshd_config
service ssh restart

# install dropbear
#apt-get -y update
#apt-get -y install dropbear
#sed -i 's/NO_START=1/NO_START=0/g' /etc/default/dropbear
#sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=443/g' /etc/default/dropbear
#sed -i 's/DROPBEAR_EXTRA_ARGS=/DROPBEAR_EXTRA_ARGS="-p 109 -p 110"/g' /etc/default/dropbear
#echo "/bin/false" >> /etc/shells
#echo "/usr/sbin/nologin" >> /etc/shells
#service ssh restart
#service dropbear restart

apt-get install dropbear
sed -i 's/NO_START=1/NO_START=0/g' /etc/default/dropbear
sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=80/g' /etc/default/dropbear
sed -i 's/DROPBEAR_EXTRA_ARGS=/DROPBEAR_EXTRA_ARGS="-p 443"/g' /etc/default/dropbear
echo "/bin/false" >> /etc/shells
echo "/usr/sbin/nologin" >> /etc/shells
sed -i 's/DROPBEAR_BANNER=""/DROPBEAR_BANNER="/etc/issue.net"/g' /etc/default/dropbear
service ssh restart
service dropbear restart
service dropbear restart
service ssh restart

# upgrade dropbear 2012.55
#apt-get install zlib1g-dev
#wget https://matt.ucc.asn.au/dropbear/releases/dropbear-2012.55.tar.bz2
#bzip2 -cd dropbear-2012.55.tar.bz2 | tar xvf -
#cd dropbear-2012.55
#./configure
#make && make install
#mv /usr/sbin/dropbear /usr/sbin/dropbear1
#ln /usr/local/sbin/dropbear /usr/sbin/dropbear
#service dropbear restart

# upgade dropbear
apt-get install zlib1g-dev
wget $source/dropbear-2016.74.tar.bz2
bzip2 -cd dropbear-2016.74.tar.bz2 | tar xvf -
cd dropbear-2016.74
./configure
make && make install
mv /usr/sbin/dropbear /usr/sbin/dropbear.old
ln /usr/local/sbin/dropbear /usr/sbin/dropbear
cd && rm -rf dropbear-2016.74 && rm -rf dropbear-2016.74.tar.bz2

# install vnstat gui
cd /home/vps/public_html/
wget $source/vnstat_php_frontend-1.5.1.tar.gz
tar xvfz vnstat_php_frontend-1.5.1.tar.gz
rm vnstat_php_frontend-1.5.1.tar.gz
mv vnstat_php_frontend-1.5.1 vnstat
cd vnstat
sed -i "s/eth0/$ether/g" config.php
sed -i "s/\$iface_list = array('venet0', 'sixxs');/\$iface_list = array($ether);/g" config.php
sed -i "s/\$language = 'nl';/\$language = 'en';/g" config.php
sed -i 's/Internal/Internet/g' config.php
sed -i '/SixXS IPv6/d' config.php
cd

#if [[ $ether = "eth0" ]]; then
#	wget -O /etc/iptables.conf $source/iptables.up.rules.eth0
#else
#	wget -O /etc/iptables.conf $source/iptables.up.rules.venet0
#fi

#sed -i $MYIP2 /etc/iptables.conf;
#iptables-restore < /etc/iptables.conf;

# block all port except
sed -i '$ i\iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT' /etc/rc.local
sed -i '$ i\iptables -A OUTPUT -d 127.0.0.1 -j ACCEPT' /etc/rc.local
sed -i '$ i\iptables -A OUTPUT -p tcp -m tcp --dport 21 -j ACCEPT' /etc/rc.local
sed -i '$ i\iptables -A OUTPUT -p tcp -m tcp --dport 22 -j ACCEPT' /etc/rc.local
sed -i '$ i\iptables -A OUTPUT -p tcp -m tcp --dport 53 -j ACCEPT' /etc/rc.local
sed -i '$ i\iptables -A OUTPUT -p tcp -m tcp --dport 80 -j ACCEPT' /etc/rc.local
sed -i '$ i\iptables -A OUTPUT -p tcp -m tcp --dport 81 -j ACCEPT' /etc/rc.local
sed -i '$ i\iptables -A OUTPUT -p tcp -m tcp --dport 109 -j ACCEPT' /etc/rc.local
sed -i '$ i\iptables -A OUTPUT -p tcp -m tcp --dport 110 -j ACCEPT' /etc/rc.local
sed -i '$ i\iptables -A OUTPUT -p tcp -m tcp --dport 143 -j ACCEPT' /etc/rc.local
sed -i '$ i\iptables -A OUTPUT -p tcp -m tcp --dport 443 -j ACCEPT' /etc/rc.local
sed -i '$ i\iptables -A OUTPUT -p tcp -m tcp --dport 1194 -j ACCEPT' /etc/rc.local
sed -i '$ i\iptables -A OUTPUT -p tcp -m tcp --dport 3128 -j ACCEPT' /etc/rc.local
sed -i '$ i\iptables -A OUTPUT -p tcp -m tcp --dport 8000 -j ACCEPT' /etc/rc.local
sed -i '$ i\iptables -A OUTPUT -p tcp -m tcp --dport 8080 -j ACCEPT' /etc/rc.local
sed -i '$ i\iptables -A OUTPUT -p tcp -m tcp --dport 10000 -j ACCEPT' /etc/rc.local
sed -i '$ i\iptables -A OUTPUT -p tcp -m tcp --dport 55 -j ACCEPT' /etc/rc.local
sed -i '$ i\iptables -A OUTPUT -p udp -m udp --dport 2500 -j ACCEPT' /etc/rc.local
sed -i '$ i\iptables -A OUTPUT -p udp -m udp --dport 53 -j ACCEPT' /etc/rc.local
sed -i '$ i\iptables -A OUTPUT -p udp -m udp -j DROP' /etc/rc.local
sed -i '$ i\iptables -A OUTPUT -p tcp -m tcp -j DROP' /etc/rc.local

# install fail2ban
apt-get update;apt-get -y install fail2ban;service fail2ban restart

# install squid3
apt-get -y install squid3
wget -O /etc/squid3/squid.conf $source/squid3.conf
sed -i $MYIP2 /etc/squid3/squid.conf;
service squid3 restart

# install webmin
cd
#wget -O webmin-current.deb http://prdownloads.sourceforge.net/webadmin/webmin_1.760_all.deb
wget -O webmin-current.deb $source/webmin-current.deb
dpkg -i --force-all webmin-current.deb
apt-get -y -f install;
#sed -i 's/ssl=1/ssl=0/g' /etc/webmin/miniserv.conf
rm -f /root/webmin-current.deb
apt-get -y --force-yes -f install libxml-parser-perl
service webmin restart
service vnstat restart

# install pptp vpn
wget -O /root/pptp.sh $source/pptp.sh
chmod +x pptp.sh
./pptp.sh

# Instal (D)DoS Deflateif [ -d '/usr/local/ddos' ]; then	echo; echo; echo "Please un-install the previous version first"	exit 0else	mkdir /usr/local/ddosficlearecho; echo 'Installing DOS-Deflate 0.6'; echoecho; echo -n 'Downloading source files...'wget -q -O /usr/local/ddos/ddos.conf http://www.inetbase.com/scripts/ddos/ddos.confecho -n '.'wget -q -O /usr/local/ddos/LICENSE http://www.inetbase.com/scripts/ddos/LICENSEecho -n '.'wget -q -O /usr/local/ddos/ignore.ip.list http://www.inetbase.com/scripts/ddos/ignore.ip.listecho -n '.'wget -q -O /usr/local/ddos/ddos.sh http://www.inetbase.com/scripts/ddos/ddos.shchmod 0755 /usr/local/ddos/ddos.shcp -s /usr/local/ddos/ddos.sh /usr/local/sbin/ddosecho '...done'echo; echo -n 'Creating cron to run script every minute.....(Default setting)'/usr/local/ddos/ddos.sh --cron > /dev/null 2>&1echo '.....done'echo; echo 'Installation has completed.'echo 'Config file is at /usr/local/ddos/ddos.conf'echo 'Please send in your comments and/or suggestions to zaf@vsnl.com' # download scriptcdwget -O /usr/bin/motd "https://raw.githubusercontent.com/fluxo7/m.e.n.u/master/method1/motd"wget -O /usr/bin/benchmark "https://raw.githubusercontent.com/fluxo7/m.e.n.u/master/method1/benchmark.sh"wget -O /usr/bin/speedtest "https://raw.githubusercontent.com/fluxo7/m.e.n.u/master/method1/speedtest_cli.py"wget -O /usr/bin/ps-mem "https://raw.githubusercontent.com/fluxo7/m.e.n.u/master/method1/ps_mem.py"wget -O /usr/bin/dropmon "https://raw.githubusercontent.com/fluxo7/m.e.n.u/master/method1/dropmon.sh"wget -O /usr/bin/menu "https://raw.githubusercontent.com/fluxo7/m.e.n.u/master/menu.sh"wget -O /usr/bin/user-active-list "https://raw.githubusercontent.com/fluxo7/m.e.n.u/master/method1/user-active-list.sh"wget -O /usr/bin/user-add "https://raw.githubusercontent.com/fluxo7/m.e.n.u/master/method1/user-add.sh"wget -O /usr/bin/user-add-pptp "https://raw.githubusercontent.com/fluxo7/m.e.n.u/master/method1/menu/user-add-pptp.sh"wget -O /usr/bin/user-del "https://raw.githubusercontent.com/fluxo7/m.e.n.u/master/method1/user-del.sh"wget -O /usr/bin/disable-user-expire "https://raw.githubusercontent.com/fluxo7/m.e.n.u/master/method1/disable-user-expire.sh"wget -O /usr/bin/delete-user-expire "https://raw.githubusercontent.com/fluxo7/m.e.n.u/master/method1/delete-user-expire.sh"wget -O /usr/bin/banned-user "https://raw.githubusercontent.com/fluxo7/m.e.n.u/master/method1/banned-user.sh"wget -O /usr/bin/unbanned-user "https://raw.githubusercontent.com/fluxo7/m.e.n.u/master/method1/unbanned-user.sh"wget -O /usr/bin/user-expire-list "https://raw.githubusercontent.com/fluxo7/m.e.n.u/master/method1/user-expire-list.sh"wget -O /usr/bin/user-gen "https://raw.githubusercontent.com/fluxo7/m.e.n.u/master/method1/user-gen.sh"wget -O /usr/bin/userlimit.sh "https://raw.githubusercontent.com/fluxo7/m.e.n.u/master/method1/userlimit.sh"wget -O /usr/bin/userlimitssh.sh "https://raw.githubusercontent.com/fluxo7/m.e.n.u/master/method1/userlimitssh.sh"wget -O /usr/bin/user-list "https://raw.githubusercontent.com/fluxo7/m.e.n.u/master/method1/user-list.sh"wget -O /usr/bin/user-login "https://raw.githubusercontent.com/fluxo7/m.e.n.u/master/method1/user-login.sh"wget -O /usr/bin/user-pass "https://raw.githubusercontent.com/fluxo7/m.e.n.u/master/method1/user-pass.sh"wget -O /usr/bin/user-renew "https://raw.githubusercontent.com/fluxo7/m.e.n.u/master/method1/user-renew.sh"wget -O /usr/bin/clearcache.sh "https://raw.githubusercontent.com/fluxo7/m.e.n.u/master/method1/clearcache.sh"wget -O /usr/bin/bannermenu "https://raw.githubusercontent.com/fluxo7/m.e.n.u/master/method1/bannermenu"cd #rm -rf /etc/cron.weekly/#rm -rf /etc/cron.hourly/#rm -rf /etc/cron.monthly/rm -rf /etc/cron.daily/wget -O /root/passwd "https://raw.githubusercontent.com/fluxo7/m.e.n.u/master/method1/passwd.sh"chmod +x /root/passwdecho "01 23 * * * root /root/passwd" > /etc/cron.d/passwd echo "*/30 * * * * root service dropbear restart" > /etc/cron.d/dropbearecho "00 23 * * * root /usr/bin/disable-user-expire" > /etc/cron.d/disable-user-expireecho "0 */12 * * * root /sbin/reboot" > /etc/cron.d/reboot#echo "00 01 * * * root echo 3 > /proc/sys/vm/drop_caches && swapoff -a && swapon -a" > /etc/cron.d/clearcacheram3swapecho "*/30 * * * * root /usr/bin/clearcache.sh" > /etc/cron.d/clearcache1 cdchmod +x /usr/bin/motdchmod +x /usr/bin/benchmarkchmod +x /usr/bin/speedtestchmod +x /usr/bin/ps-mem#chmod +x /usr/bin/autokillchmod +x /usr/bin/dropmonchmod +x /usr/bin/menuchmod +x /usr/bin/user-active-listchmod +x /usr/bin/user-addchmod +x /usr/bin/user-add-pptpchmod +x /usr/bin/user-delchmod +x /usr/bin/disable-user-expirechmod +x /usr/bin/delete-user-expirechmod +x /usr/bin/banned-userchmod +x /usr/bin/unbanned-userchmod +x /usr/bin/user-expire-listchmod +x /usr/bin/user-genchmod +x /usr/bin/userlimit.shchmod +x /usr/bin/userlimitssh.shchmod +x /usr/bin/user-listchmod +x /usr/bin/user-loginchmod +x /usr/bin/user-passchmod +x /usr/bin/user-renewchmod +x /usr/bin/clearcache.shchmod +x /usr/bin/bannermenucd

# swap ram
dd if=/dev/zero of=/swapfile bs=1024 count=1024k
# buat swap
mkswap /swapfile
# jalan swapfile
swapon /swapfile
#auto star saat reboot
wget $source/fstab
mv ./fstab /etc/fstab
chmod 644 /etc/fstab
sysctl vm.swappiness=10
#permission swapfile
chown root:root /swapfile 
chmod 0600 /swapfile
cd

#ovpn
wget -O ovpn.sh $source/installovpn.sh
chmod +x ovpn.sh
./ovpn.sh
rm ./ovpn.sh

echo "deenie" > /etc/openvpn/pass.txt

usermod -s /bin/false mail
echo "mail:deenie" | chpasswd
useradd -s /bin/false -M deenie11
echo "deenie11:deenie" | chpasswd
# finishing
chown -R www-data:www-data /home/vps/public_html
service cron restart
service nginx start
service php5-fpm start
service vnstat restart
service snmpd restart
service ssh restart
service dropbear restart
service fail2ban restart
service squid3 restart
service webmin restart

cd
rm -f /root/.bash_history && history -c
echo "unset HISTFILE" >> /etc/profile

# info
clear
echo "Autoscript Edited elang overdosis and yusuf ardiansyah:" | tee log-install.txt
echo "=======================================================" | tee -a log-install.txt
echo "Service :" | tee -a log-install.txt
echo "---------" | tee -a log-install.txt
echo "OpenSSH  : 22, 143" | tee -a log-install.txt
echo "Dropbear : 443, 80" | tee -a log-install.txt
echo "Squid3   : 8080 limit to IP $MYIP" | tee -a log-install.txt
#echo "OpenVPN  : TCP 1194 (client config : http://$MYIP:81/client.ovpn)" | tee -a log-install.txt
echo "badvpn   : badvpn-udpgw port 7300" | tee -a log-install.txt
echo "PPTP VPN : TCP 1723" | tee -a log-install.txt
echo "nginx    : 81" | tee -a log-install.txt
echo "" | tee -a log-install.txt
echo "Tools :" | tee -a log-install.txt
echo "-------" | tee -a log-install.txt
echo "axel, bmon, htop, iftop, mtr, rkhunter, nethogs: nethogs $ether" | tee -a log-install.txt
echo "" | tee -a log-install.txt
echo "Script :" | tee -a log-install.txt
echo "--------" | tee -a log-install.txt
echo "MENU"
echo "" | tee -a log-install.txt
echo "Fitur lain :" | tee -a log-install.txt
echo "------------" | tee -a log-install.txt
echo "Webmin            : http://$MYIP:10000/" | tee -a log-install.txt
echo "vnstat            : http://$MYIP:81/vnstat/ [Cek Bandwith]" | tee -a log-install.txt
#echo "MRTG              : http://$MYIP:81/mrtg/" | tee -a log-install.txt
echo "Timezone          : Asia/Jakarta " | tee -a log-install.txt
echo "Fail2Ban          : [on]" | tee -a log-install.txt
echo "DDoS Deflate.     : [on] Install di menu no 37" | tee -a log-install.txt
echo "Block Torrent     : [off]" | tee -a log-install.txt
echo "Ocs panel reseller: Install di menu no 37"
echo "IPv6              : [off]" | tee -a log-install.txt
echo "Auto Lock User Expire tiap jam 00:00" | tee -a log-install.txt
echo "Auto Reboot tiap jam 00:00 dan jam 12:00" | tee -a log-install.txt
echo "" | tee -a log-install.txt

if [[ $vps = "zvur" ]]; then
	echo "ALL SUPPORTED BY CLIENT VPS" | tee -a log-install.txt
else
	echo "ALL SUPPORTED BY TEAM HACKER" | tee -a log-install.txt
	
fi
echo "Credit to all developers script, Yusuf ardiansyah" | tee -a log-install.txt
echo "Thanks to Allah swt" | tee -a log-install.txt
echo "" | tee -a log-install.txt
echo "Log Instalasi --> /root/log-install.txt" | tee -a log-install.txt
echo "" | tee -a log-install.txt
echo "SILAHKAN REBOOT VPS ANDA !" | tee -a log-install.txt
echo "=======================================================" | tee -a log-install.txt
cd ~/
rm -f /root/cinta7.sh
rm -f /root/pptp.sh
rm -f /root/ovpn.sh
rm -f /root/dropbear-2012.55.tar.bz2
rm -rf /root/dropbear-2012.55
rm -f /root/IP
rm -f /root/IPcarding
