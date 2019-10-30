/*
	dpi.c for TrendMicro DPI engine usage
	- all DPI function control and service control
*/

#include "bwdpi.h"

int check_daulwan_mode()
{
	if (nvram_match("wans_mode", "lb"))
		return 0;
	else
		return 1;
}

static int check_wan_changed()
{
	char buf[8];
	int changed = 0;
	char dev_wan[128] = {0};
	char wanType[16] = {0}, param[64] = {0};

	/* get primary wan interface name */
	FILE *f = NULL;
	if ((f = popen("mngcli get ARC_WAN_Type", "r")) != NULL) {
		fgets(wanType, sizeof(wanType), f);
		if (wanType[strlen(wanType) - 1] == '\n')
			wanType[strlen(wanType) - 1] = '\0';
		pclose(f);
		sprintf(param, "mngcli get ARC_WAN_%s00_Iface", wanType);
		if ((f = popen(param, "r")) != NULL) {
			fgets(dev_wan, sizeof(dev_wan), f);
			if (dev_wan[strlen(dev_wan) - 1] == '\n')
				dev_wan[strlen(dev_wan) - 1] = '\0';
			pclose(f);
		}
	}

	if (f_read_string(DEV_WAN, buf, sizeof(buf)) > 0)
		f_write_string(WAN_TMP, buf, 0, 0);

	if (f_read_string(WAN_TMP, buf, sizeof(buf)) > 0)
	{
		BWDPI_DBG("dev_wan=%s, buf=%s\n", dev_wan, buf);
		if (dev_wan != NULL && strstr(buf, dev_wan) == NULL)
			changed = 1;

		unlink(WAN_TMP);
	}

	dbg("[BWDPI][%s:(%d)] dev_wan=%s, buf=%s, changed=%d\n", __FUNCTION__, __LINE__, dev_wan, buf, changed);

	return changed;
}

void setup_dev_wan()
{
	char buf[8];
	int changed = check_wan_changed();
	char dev_wan[128] = {0};
	char wanType[16] = {0}, param[64] = {0};

	/* get primary wan interface name */
	FILE *f = NULL;
	if ((f = popen("mngcli get ARC_WAN_Type", "r")) != NULL) {
		fgets(wanType, sizeof(wanType), f);
		if (wanType[strlen(wanType) - 1] == '\n')
			wanType[strlen(wanType) - 1] = '\0';
		pclose(f);
		sprintf(param, "mngcli get ARC_WAN_%s00_Iface", wanType);
		if ((f = popen(param, "r")) != NULL) {
			fgets(dev_wan, sizeof(dev_wan), f);
			if (dev_wan[strlen(dev_wan) - 1] == '\n')
				dev_wan[strlen(dev_wan) - 1] = '\0';
			pclose(f);
		}
	}

	if (changed && (f_read_string(DEV_WAN, buf, sizeof(buf)) > 0))
	{
		f_write_string(DEV_WAN, dev_wan, 0, 0);
		BWDPI_DBG("dev_wan changed! dev_wan=%s\n", dev_wan);
	}
}

void save_version_of_bwdpi()
{
	char buf[12], tmp[12];
	char *i = NULL, *j = NULL;
	int num = 0;
	int sig = 0;

	memset(buf, 0, sizeof(buf));
	memset(tmp, 0, sizeof(tmp));

	if (f_exists(SIG_VER))
	{
		system("echo -n `cat /proc/nk_policy | grep Ver | cut -d: -f1 | sed s/Ver-//g | sed s/\\ #\\ policies//g` > /tmp/SIGVER");
		system("cat /tmp/SIGVER");

		if (f_read_string("/tmp/SIGVER", buf, sizeof(buf)) > 0)
		{
			if (vstrsep(buf, ".", &i, &j) != 2) {
				nvram_set("bwdpi_sig_ver", "wrong-signature");
				return;
			}
			sig = atoi(i);
			num = atoi(j);

			if (num < 10)
				snprintf(tmp, sizeof(tmp), "00%d",num);
			else if (num < 100 && num >= 10)
				snprintf(tmp, sizeof(tmp), "0%d",num);
			else if (num < 1000 && num >= 100)
				snprintf(tmp, sizeof(tmp), "%d",num);

			snprintf(buf, sizeof(buf), "%d.%s", sig, tmp);
			nvram_set("bwdpi_sig_ver", buf);
		}

		unlink("/tmp/SIGVER");
	}

	if (f_exists(DPI_VER))
	{
		system("echo -n `cat /proc/ips_info  | grep \"Engine version\" | cut -d: -f2 | sed 's/^[ \t]*//g'` > /tmp/DPIVER");
		if (f_read_string("/tmp/DPIVER", buf, sizeof(buf)) > 0)
			nvram_set("bwdpi_dpi_ver", buf);

		unlink("/tmp/DPIVER");
	}
}

void stop_bwdpi_wred_alive()
{
	system("killall -9 bwdpi_wred_alive 2>/dev/null");
}

void start_bwdpi_wred_alive()
{
	char *cmd[] = {"bwdpi_wred_alive", NULL};
	int pid;
	FILE *fd = NULL;
	char wred_alive_pid_tmp[10];
	int wred_alive_pid = 0;

	/* only support SW_MODE_ROUTER mode*/
	//if (!is_router_mode())
	//	return;

	system("pidof bwdpi_wred_alive > /tmp/bwdpi_wred_alive.pid");
	fd = fopen("/tmp/bwdpi_wred_alive.pid", "r");
	if (fd != NULL) {
		fgets(wred_alive_pid_tmp, sizeof(wred_alive_pid_tmp), fd);
		fclose(fd);
		system("rm -r /tmp/bwdpi_wred_alive.pid");
		wred_alive_pid = atoi(wred_alive_pid_tmp);
		if (wred_alive_pid == 0) {
			_eval(cmd, NULL, 0, &pid);
		}
	}
}

void stop_dpi_engine_service(int forced)
{
	int enabled = check_bwdpi_nvram_setting();
	BWDPI_DBG("forced=%d, enabled=%d\n", forced, enabled);

	// qosd, tc rule must be clean
	//stop_qosd();

	// app patrol must re-configure
	if (!forced) {
		wrs_app_service(0);
	}

	// if bwdpi function is disabled or force to stop, kill all serivces
	if (!enabled || forced) {
		stop_bwdpi_wred_alive();
		stop_dc();
		stop_wrs();
		stop_tm_qos();

		/* after remove all modules, need to remove signature, too */
		if (f_exists(APPDB) || f_exists(CATDB) || f_exists(RULEV)) {
			system("rm /tmp/bwdpi/*.db -f"); // can't use eval
		}

		/* enable hw acceleration(Runner / Flow Cache) */
		eval("fc", "enable");
		eval("fc", "flush");
	}
}

static void start_vlan_rule()
{
	// only for vlanX case
	int unit;
	char word[16], tmp[32], prefix[] = "wanXXXXXXXXXX_";

	for (unit = 0; unit < 2; unit++)
	{
		snprintf(prefix, sizeof(prefix), "wan%d_", unit);
		strlcpy(word, nvram_safe_get(strcat_r(prefix, "ifname", tmp, CCFG_NAME_LEN)), sizeof(word));
		if (strstr(word, "vlan"))
			eval("tc", "qdisc", "add", "dev", word, "root", "pfifo");
	}
}

static void start_bwdpi_db_10()
{
	// save database when traffic analyzer is enabled in 10 mins
	char *cmd[] = {"bwdpi_db_10", NULL};
	char *path = NULL;
	int pid;
	int is_run = 1;
	struct stat st;
	off_t cursize;
	FILE *fd = NULL;
	char db_10_pid_tmp[10];
	int db_10_pid = 0;

	path = BWDPI_ANA_DB;
	stat(path, &st);
	cursize = st.st_size;

	if (cursize == 0 || cursize < 5)
		is_run = 1;
	else
		is_run = 0;

	BWDPI_DBG("path=%s, cursize=%ld, is_run=%d\n", path, cursize, is_run);

	system("pidof bwdpi_db_10 > /tmp/bwdpi_db_10.pid");
	fd = fopen("/tmp/bwdpi_db_10.pid", "r");
	if (fd != NULL) {
		fgets(db_10_pid_tmp, sizeof(db_10_pid_tmp), fd);
		fclose(fd);
		system("rm -r /tmp/bwdpi_db_10.pid");
		db_10_pid = atoi(db_10_pid_tmp);
		if ((db_10_pid == 0) && is_run) {
			_eval(cmd, NULL, 0, &pid);
		}
	}
}

/*
	To turn on/off DPI features, echo with these HEX values
	APP_ID      : 0x001
	DEV_ID      : 0x002
	VIRT_PATCH  : 0x004
	WRS_APP     : 0x008
	WRS_CC      : 0x010
	WRS_SEC     : 0x020
	ANOMALY     : 0x040
	QOS         : 0x080
	APP_PATROL  : 0x100
	PATROL_TQ   : 0x200
*/
#define APP_ID     0
#define DEV_ID     1
#define VP_ID      2
#define WRS_APP    3
#define WRS_CC     4
#define WRS_SEC    5
#define ANOMALY    6
#define QOS_ID     7
#define APP_PATROL 8
#define TIME_QUOTA 9

void run_dpi_engine_service()
{
	unsigned int cmd = 0;
	char buf[8];

	BWDPI_DBG("DO run_dpi_engine_service()\n");

#if 0 /* not support load-balance mode */
	if (check_daulwan_mode() == 0) {
		BWDPI_DBG("DPI engine doesm't support load-balance mode!\n");
		//logmessage("dpi", "TrendMicro function can't use under load-balance mode!");
		return;
	}
#endif

	/* disable hw acceleration(Runner / Flow Cache) */
	eval("fc", "disable");
	eval("fc", "flush");

	int FULL = nvram_get_int("wrs_protect_enable");
	int MALS = nvram_get_int("wrs_mals_enable");
	int VP = nvram_get_int("wrs_vp_enable");
	int CC = nvram_get_int("wrs_cc_enable");

	// insert dpi engine
	start_tm_qos();

	// change wan interface
	setup_dev_wan();

	// default
	cmd = (1 << APP_ID) | (1 << DEV_ID);

	// wrs (web filter)
	if (nvram_get_int("wrs_enable"))
		cmd |= (1 << WRS_APP);

	// C&C
	if (FULL & CC)
		cmd |= (1 << WRS_CC) | (1 << WRS_APP);

	// wrs mals (web filter)
	if (FULL & MALS)
		cmd |= (1 << WRS_SEC);

	setup_wrs_conf();

	// VP and Anomaly
	if (FULL & VP)
		cmd |= (1 << VP_ID) | (1 << ANOMALY);

	// APP filters
	if (nvram_get_int("wrs_app_enable")) {
		cmd |= (1 << APP_PATROL);
		wrs_app_service(1);
	}
	else
		wrs_app_service(0);

	// adaptive qos
	if (nvram_get_int("qos_enable") && nvram_get_int("qos_type") == 1) {
		cmd |= (1 << QOS_ID);
	}

	// set dpi engine conf
	snprintf(buf, sizeof(buf), "%x", cmd);
	f_write_string(BW_DPI_SET, buf, 0, 0);
	BWDPI_DBG("buf=%s, cmd=%d(%x)\n", buf, cmd, cmd);

	// run data_colld
	start_dc(NULL);

	// run wred and wred_set_conf
	start_wrs();

	// check EULA
	tm_eula_check();

	// get engine and signature version
	save_version_of_bwdpi();

	// check wred alive
	start_bwdpi_wred_alive();

	// adaptive qos
	if (nvram_get_int("qos_enable") && nvram_get_int("qos_type") == 1) {
		restart_qosd();
	}
	else if (nvram_get_int("qos_enable") && nvram_get_int("qos_type") == 0) {
		// do nothing
	}
	else {
		stop_qosd();
	}

	// fix dead loop message when use vlanX
	start_vlan_rule();

	// save database when traffic analyzer is enabled in 10 mins
	if (nvram_get_int("bwdpi_db_enable"))
		start_bwdpi_db_10();
}

void start_dpi_engine_service()
{
	if (check_bwdpi_nvram_setting())
		run_dpi_engine_service();
}
