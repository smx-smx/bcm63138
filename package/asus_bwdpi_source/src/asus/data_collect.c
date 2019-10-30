/*
	data_collect.c for data collection in statistics,
	dcd must enabled for DPI engine function.
*/

#include "bwdpi.h"

void stop_dc()
{
	char cmd[256] = {0};
	snprintf(cmd, sizeof(cmd),"killall -9 %s 2>/dev/null", DATACOLLD);
	system(cmd);
	if (f_exists("/var/conf_serv_sock"))
		eval("rm", "-f", "/var/conf_serv_sock");
}

void start_dc(char *path)
{
	char buf[512];
	FILE *fd = NULL;
	char cmd[128], dcd_pid_tmp[10];
	int dcd_pid = 0;

	/* only support SW_MODE_ROUTER mode*/
	//if (!is_router_mode())
	//	return;

	if (!f_exists(DPI_CERT))
		eval("cp", "/usr/bwdpi/ntdasus2014.cert", DPI_CERT, "-f");

	if (path != NULL)
		snprintf(buf, sizeof(buf), "%s", path);
	else
		snprintf(buf, sizeof(buf), "LD_LIBRARY_PATH=%s %s -i 3600 -p 43200 -b -d %s &", TMP_BWDPI, DATACOLLD, TMP_BWDPI);

	snprintf(cmd, sizeof(cmd), "pidof %s > /tmp/dcd.pid", DATACOLLD);
	system(cmd);
	fd = fopen("/tmp/dcd.pid", "r");
	if (fd != NULL) {
		fgets(dcd_pid_tmp, sizeof(dcd_pid_tmp), fd);
		fclose(fd);
		system("rm -r /tmp/dcd.pid");
		dcd_pid = atoi(dcd_pid_tmp);
		if (dcd_pid == 0) {
			stop_dc();
			chdir(TMP_BWDPI);
			BWDPI_DBG("buf=%s\n", buf);
			system(buf);
			chdir("/");
		}
	}
}

int data_collect_main(char *cmd, char *path)
{
	if (!strcmp(cmd, "restart")) {
		stop_dc();
		start_dc(path);
	}
	else if (!strcmp(cmd, "stop")) {
		stop_dc();
	}
	else if (!strcmp(cmd, "start")) {
		start_dc(path);
	}

	return 1;
}
