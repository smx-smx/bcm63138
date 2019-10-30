#!/bin/sh

wget_timeout=`nvram get apps_wget_timeout`
wget_options="-q -t 2 -T $wget_timeout --no-check-certificate"

nvram set sig_state_upgrade=0 # INITIALIZING
nvram set sig_state_error=0

#openssl support rsa check
#rsa_enabled=`nvram show | grep rc_support | grep HTTPS`
rsa_enabled=1

touch /tmp/update_url
update_url=`cat /tmp/update_url`
#update_url="http://192.168.123.198"

sig_file=`nvram get SKU`_`nvram get sig_state_info`_un.zip
if [ "$rsa_enabled" != "" ]; then
sig_rsasign=`nvram get SKU`_`nvram get sig_state_info`_rsa.zip
fi
echo "$sig_file" > /tmp/sig_upgrade.log
echo "$sig_rsasign" >> /tmp/sig_upgrade.log

# get signature zip file
forsq=`nvram get apps_sq`
#urlpath=`nvram get sig_state_url`
echo 3 > /proc/sys/vm/drop_caches
if [ "$forsq" == "1" ]; then
	echo "---- wget trf sq ----"
	echo "---- wget trf sq ----" >> /tmp/sig_upgrade.log
	wget $wget_options https://dlcdnets.asus.com/pub/ASUS/LiveUpdate/Release/Wireless_SQ/$sig_file -O /tmp/rule.trf
	if [ "$rsa_enabled" != "" ]; then
		echo "---- wget rsa sq ----"
		wget $wget_options https://dlcdnets.asus.com/pub/ASUS/LiveUpdate/Release/Wireless_SQ/$sig_rsasign -O /tmp/rsasign.bin
	fi
else
	echo "---- wget trf Real ----"
	echo "---- wget trf Real ----" >> /tmp/sig_upgrade.log
	wget $wget_options https://dlcdnets.asus.com/pub/ASUS/wireless/ASUSWRT/$sig_file -O /tmp/rule.trf
	if [ "$rsa_enabled" != "" ]; then
		echo "---- wget rsa Real ----"
		wget $wget_options https://dlcdnets.asus.com/pub/ASUS/wireless/ASUSWRT/$sig_rsasign -O /tmp/rsasign.bin
	fi
fi	

if [ "$?" != "0" ]; then	#download failure
	echo "---- Download and mv trf Failure ----"
	echo "---- Download and mv trf Failure ----" >> /tmp/sig_upgrade.log
	nvram set sig_state_error=1
else
	nvram set sig_state_upgrade=2
	echo "---- Download and mv trf OK ----"
	echo "---- Download and mv trf OK ----" >> /tmp/sig_upgrade.log
	if [ "$rsa_enabled" != "" ]; then
		nvram set bwdpi_rsa_check=0
		rsasign_sig_check /tmp/rule.trf
		sleep 1
	fi

	if [ "$rsa_enabled" != "" ]; then
		rsasign_check_ret=`nvram get bwdpi_rsa_check`
	fi

	if [ "$rsasign_check_ret" == "1" ]; then
		echo "---- sig check OK ----" >> /tmp/sig_upgrade.log
		if [ -f /data/signature/rule.trf ];then
			echo "---- sig rule mv /tmp to /data/signature ----"
			echo "---- sig rule mv /tmp to /data/signature ----" >> /tmp/sig_upgrade.log
			rm /data/signature/rule.trf
			mv /tmp/rule.trf /data/signature/rule.trf
		else
			echo "---- sig rule mv data ----"
			echo "---- sig rule mv data ----" >> /tmp/sig_upgrade.log
			mkdir /data/signature
			mv /tmp/rule.trf /data/signature/rule.trf
		fi
		if [ "$1" == "" ];then
			echo "Do restart_wrs"
			echo "Do restart_wrs" >> /tmp/sig_upgrade.log
			#rc rc_service restart_wrs
			bwdpi service stop
			bwdpi service start
			nvram set sig_update_t=`date +%s`	#set timestamp for download signature and restart_wrs
		else
			echo "do nothing..." >> /tmp/sig_upgrade.log
		fi
	else
		echo "---- sig rsa check error ----"
		echo "---- sig rsa check error ----" >> /tmp/sig_upgrade.log
		nvram set sig_state_error=3	# wrong sig trf
	fi
fi

rm -f /tmp/rsasign.bin

nvram set sig_state_upgrade=1
