#!/bin/sh
# ASUS app unmount script

if [ -z "$1" ]; then
	echo "Usage: app_unmount.sh [device name]"
	exit 1
fi

nvram set apps_state_stop=0 # INITIALIZING
nvram set apps_state_error=0
APPS_INSTALL_FOLDER=`nvram get apps_install_folder`
SWAP_ENABLE=`nvram get apps_swap_enable`
SWAP_FILE=`nvram get apps_swap_file`
APPS_MOUNTED_PATH=`nvram get apps_mounted_path`

devs=`lsblk -o KNAME |grep $1| awk '{print "/dev/"$1}'`
for dev in $devs 
do
	APPS_UNMOUNT_PATH=`mount |grep "${dev} on " |awk '{print $3}'`
	if [ "${APPS_MOUNTED_PATH}" == "${APPS_UNMOUNT_PATH}" ]; then
		nvram set apps_state_stop=1 # STOPPING
		# stop all APPs by order.
		app_init_run.sh allpkg stop

		nvram set apps_state_stop=2 # REMOVING_SWAP
		if [ "$SWAP_ENABLE" == "1" ] && [ -f "$APPS_MOUNTED_PATH/$APPS_INSTALL_FOLDER/$SWAP_FILE" ]; then
			swapoff $APPS_MOUNTED_PATH/$APPS_INSTALL_FOLDER/$SWAP_FILE
			rm -rf $APPS_MOUNTED_PATH/$APPS_INSTALL_FOLDER/$SWAP_FILE
		fi
		nvram set apps_state_stop=3 # FINISHED
		break
	fi
done
