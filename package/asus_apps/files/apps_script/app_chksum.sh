#!/bin/sh
# ASUS Checksum script

APPS_INSTALL_FOLDER=`nvram get apps_install_folder`
APPS_MOUNTED_PATH=`nvram get apps_mounted_path`
APPS_DEV=`nvram get apps_dev`
CHECKSUM_PREFIX="checksum_"
if [ ! -z $APPS_DEV ]; then
	DEV_SN=`lsblk -o KNAME,SERIAL -n | grep ${APPS_DEV:0:3} | head -1 | awk '{print $2}'`
	CHECKSUM_PREFIX="checksum_"$DEV_SN"_"
fi

CHECKSUM_FOLDER="bin etc/init.d etc/asus_script etc/apps_asus_script"
for folder in $CHECKSUM_FOLDER
do
	path=$APPS_MOUNTED_PATH/$APPS_INSTALL_FOLDER/$folder
	files=`find $path -maxdepth 1 -type f`
	for file in $files
	do
		VarName=$CHECKSUM_PREFIX`basename $file`
		CheckSum=`md5sum $file | awk '{print $1}'`
		nvram set $VarName"="$CheckSum
	done
done
file="$APPS_MOUNTED_PATH/$APPS_INSTALL_FOLDER/.asusrouter"
if [ -f $file ];
then
	VarName=$CHECKSUM_PREFIX`basename $file`
	CheckSum=`md5sum $file | awk '{print $1}'`
	nvram set $VarName"="$CheckSum
fi
nvram commit
