
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include "asus_rc.h"
#include "arcgpl.h"

#define _dprintf(args...)	do { } while(0)
extern int pids(char *appname);

// string = S20transmission -> return value = transmission.
int get_apps_name(const char *string)
{
	char *ptr;

	if(string == NULL)
		return 0;

	if((ptr = rindex(string, '/')) != NULL)
		++ptr;
	else
		ptr = (char*) string;
	if(ptr[0] != 'S')
		return 0;
	++ptr; // S.

	while(ptr != NULL){
		if(isdigit(ptr[0]))
			++ptr;
		else
			break;
	}

	printf("%s", ptr);
	return 1;
}

int f_read(const char *path, void *buffer, int max)
{
	int f;
	int n;

	if ((f = open(path, O_RDONLY)) < 0) return -1;
	n = read(f, buffer, max);
	close(f);
	return n;
}

int f_read_string(const char *path, char *buffer, int max)
{
	if (max <= 0) return -1;
	int n = f_read(path, buffer, max - 1);
	buffer[(n > 0) ? n : 0] = 0;
	return n;
}

int main(int argc, char *argv[])
{
	char *base;
	int f;
	char buffer[256];
#define get_asus_para(name) arcgpl_cfg_get("ASUS_" name, buffer, sizeof(buffer))
#define set_asus_para(name, value) arcgpl_cfg_set("ASUS_" name, value)

	if ((f = open("/dev/null", O_RDWR)) < 0) {
	}
	else if(f < 3) {
		dup(f);
		dup(f);
	}
	else {
		close(f);
	}

	base = strrchr(argv[0], '/');
	base = base ? base + 1 : argv[0];
	
	if(!strcmp(base, "get_apps_name")){
		if(argc != 2){
			printf("Usage: get_apps_name [File name]\n");
			return 0;
		}
		return get_apps_name(argv[1]);
	}
	else if (!strcmp(base, "chk_app_state")) {
#define PID_FILE "/var/run/chk_app_state.pid"
		FILE *fp;
		char chk_value[4];

		if(f_read_string(PID_FILE, chk_value, 4) > 0
				&& atoi(chk_value) != getpid()){
			_dprintf("Already running!\n");
			return 0;
		}

		if((fp = fopen(PID_FILE, "w")) == NULL){
			_dprintf("Can't open the pid file!\n");
			return 0;
		}

		fprintf(fp, "%d", getpid());
		fclose(fp);

		memset(chk_value, 0, 4);
		strncpy(chk_value, get_asus_para("apps_state_switch"), 4);
		if(strcmp(chk_value, "")){
			if(atoi(chk_value) != APPS_SWITCH_FINISHED && !pids("app_switch.sh")){
				_dprintf("Don't have the switch script.\n");
				set_asus_para("apps_state_switch", "");
			}

			unlink(PID_FILE);
			return 0;
		}

		memset(chk_value, 0, 4);
		strncpy(chk_value, get_asus_para("apps_state_install"), 4);
		if(strcmp(chk_value, "")){
			if(atoi(chk_value) != APPS_INSTALL_FINISHED && !pids("app_install.sh")){
				_dprintf("Don't have the install script.\n");
				set_asus_para("apps_state_install", "");
			}

			unlink(PID_FILE);
			return 0;
		}

		memset(chk_value, 0, 4);
		strncpy(chk_value, get_asus_para("apps_state_upgrade"), 4);
		if(strcmp(chk_value, "")){
			if(atoi(chk_value) != APPS_UPGRADE_FINISHED && !pids("app_upgrade.sh")){
				_dprintf("Don't have the upgrade script.\n");
				set_asus_para("apps_state_upgrade", "");
			}

			unlink(PID_FILE);
			return 0;
		}

		memset(chk_value, 0, 4);
		strncpy(chk_value, get_asus_para("apps_state_enable"), 4);
		if(strcmp(chk_value, "")){
			if(atoi(chk_value) != APPS_ENABLE_FINISHED && !pids("app_set_enabled.sh")){
				_dprintf("Don't have the enable script.\n");
				set_asus_para("apps_state_enable", "");
			}

			unlink(PID_FILE);
			return 0;
		}

		unlink(PID_FILE);
		return 0;
	}

	return 0;
}

