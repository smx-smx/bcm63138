#!/bin/sh
# ASUS Verify Checksum script

APPS_INSTALL_FOLDER=`nvram get apps_install_folder`
APPS_MOUNTED_PATH=$1
APPS_DEV=$2
CHECKSUM_PREFIX="checksum_"

if [ ! -z $APPS_DEV ]; then
	DEV_SN=`lsblk -o KNAME,SERIAL -n | grep ${APPS_DEV:0:3} | head -1 | awk '{print $2}'`
	testPara=`mng_cli test "ASUS_checksum_"${DEV_SN}`
	if [ $testPara == "existed" ]; then
		CHECKSUM_PREFIX="checksum_"$DEV_SN"_"
	fi
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
		VfySum=`nvram get $VarName`
		if [ $VfySum"" != "" ] && [ "$VfySum" != "$CheckSum" ];
		then
			echo $file" corrupted!!"
			nvram set apps_mounted_path=$APPS_MOUNTED_PATH
			nvram set apps_file_corrupted=1
			exit 1
		fi
	done
done
file="$APPS_MOUNTED_PATH/$APPS_INSTALL_FOLDER/.asusrouter"
if [ -f $file ];
then
	VarName=$CHECKSUM_PREFIX`basename $file`
	CheckSum=`md5sum $file | awk '{print $1}'`
	VfySum=`nvram get $VarName`
	if [ $VfySum"" == "" ];
	then
		echo "Factory reset! Inform user to reinstall app!"
		nvram set apps_mounted_path=$APPS_MOUNTED_PATH
		nvram set apps_file_corrupted=2
		exit 1
	fi
	if [ "$VfySum" != "$CheckSum" ];
	then
		echo $file" corrupted!!"
		nvram set apps_mounted_path=$APPS_MOUNTED_PATH
		nvram set apps_file_corrupted=1
		exit 1
	fi
fi
nvram set apps_file_corrupted=0