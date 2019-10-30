/*
	iqos.c for TrendMicro iQoS / qosd
	iqos :
		only run DPI engine related services
	qosd :
		only run qosd and build tc rule
*/

#include "bwdpi.h"

/*
	check dpi moudle exists or not
*/
static int dpi_module_check()
{
	if (!f_exists(DEV_WAN) || !f_exists(QOS_WAN))
		return 0;
	else
		return 1;
}

/*
	usage in qosd for checking wan interface and workaround
*/
void check_qosd_wan_setting(char *dev_wan, int len)
{
	char dev[128] = {0};
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
			fgets(dev, sizeof(dev), f);
			if (dev[strlen(dev) - 1] == '\n')
				dev[strlen(dev) - 1] = '\0';
			pclose(f);
		}
	}
	strlcpy(dev_wan, dev, len);
	BWDPI_DBG("dev_wan=%s, dev=%s\n", dev_wan, dev);
}

static void set_prio_appcat(FILE *fp, char *buf, int count)
{
	char *g = NULL, *p = NULL;
	int cat_rate[8] = {5, 20, 10, 5, 4, 3, 2, 1}; // initial value

	// reserved rate
	fprintf(fp, "[%d, %d%s]\n", count, cat_rate[count], "%");

	// app catid
	g = buf;

	// fixed app rule
	if (count == 0) fputs("rule=18\nrule=19\n", fp);
	if (count == 4) fputs("rule=28\nrule=29\nrule=30\nrule=31\nrule=32\nrule=33\nrule=34\nrule=35\nrule=36\nrule=37\nrule=38\nrule=39\nrule=40\nrule=41\nrule=42\nrule=43\n", fp);
	if (count == 5) fputs("rule=12\n", fp);

	if (!strcmp(buf, "")) {
		fprintf(fp, "rule=na\n");
	}
	else {
		while (g) {
			if ((p = strsep(&g, ",")) != NULL) {
				fprintf(fp, "rule=%s\n", p);
			}
		}
	}
}

static void set_prio_app(FILE *fp)
{
	char *p = NULL;
	char *g = NULL;
	char *buf = NULL;
	int count = 0;

	/* ASUSWRT
		bwdpi_app_rulelist :
		[PRIO 0]<[PRIO 1]<[PRIO 2]<[PRIO 3]<[PRIO 4]<[PRIO 5]<[PRIO 6]<[PRIO 7]<<[type]
		[PRIO x] = cat1,cat2,...
		ex. default : 9,20<4<0,5,6,15<8<13,24<10,11,17<<1,3,14<<web
	*/

	g = buf = strdup(nvram_safe_get("bwdpi_app_rulelist"));

	while (g && count < 8) {
		if ((p = strsep(&g, "<")) == NULL) break;
		set_prio_appcat(fp, p, count);
		count++;
	}

	if (buf) free(buf);
}

static void set_prio_dev(FILE *fp)
{
	fputs("{0}\n", fp);
	fputs("{1}\n", fp);
	fputs("{2}\nfam=1\nfam=2\nfam=3\nfam=4\nfam=5\nfam=6\nfam=7\nfam=8\n", fp);
	fputs("{3}\nfam=na\n", fp);
	fputs("{4}\n", fp);
}

void setup_qos_conf()
{
	FILE *fp = NULL;
	double ibw ,obw;

	// because of UI is kbps, but setting file is KBps
	ibw = strtoul(nvram_safe_get("qos_ibw"), NULL, 10) / 8;
	obw = strtoul(nvram_safe_get("qos_obw"), NULL, 10) / 8;

	// For AiHome APP spec
	if (ibw == 0) {
		ibw = 10 * 1024 * 1024 / 8; // 10Gbps = 1.25GBps
		printf("set ibw into 10Gbps due to unlimited\n");
	}

	// For AiHome APP spec
	if (obw == 0) {
		obw = 10 * 1024 * 1024 / 8; // 10Gbps = 1.25GBps
		printf("set ibw obw into 10Gbps due to unlimited\n");
	}

	if ((fp = fopen(QOS_CONF, "w")) == NULL) {
		printf("FAIL to open %s\n", QOS_CONF);
		return;
	}

	fprintf(fp, "ceil_down=%.3fkbps\n", ibw);
	fprintf(fp, "ceil_up=%.3fkbps\n", obw);

	// set app rule
	set_prio_app(fp);

	// set dev rule (cat or fam)
	set_prio_dev(fp);

	// close file
	if (fp) fclose(fp);
}

void stop_tm_qos()
{
	// step1. remove module
	system("rmmod tdts_udbfw.ko 2>/dev/null");
	system("rmmod tdts_udb.ko 2>/dev/null");
	system("rmmod tdts.ko 2>/dev/null");

	// step2. remove dev nodes
	eval("rm", "-f", "/dev/detector");
	eval("rm", "-f", "/dev/idpfw");

	// step3. clean DPI engine mangle rule
	eval("iptables", "-t", "mangle", "-F", "BWDPI_FILTER");
	eval("iptables", "-t", "mangle", "-F", "PREROUTING");
}

/*
	check signature update or not
	if NO , tar original source; if YES, tar new source.
*/
static void run_signature_check()
{
	int checked = nvram_get_int("bwdpi_rsa_check");
	char *path = DATABASE;

	// step1. check debug mode or not
	if (nvram_get_int("bwdpi_debug_path")) {
		BWDPI_DBG("1 - run signature from %s\n", path);
		chdir(TMP_BWDPI);
		eval(AGENT, "-g", "-r", path);
		chdir("/");
		goto final;
	}

	// step2. signature update or not
	if (checked && (f_exists("/data/signature/rule.trf"))) {
		path = "/data/signature/rule.trf";
		BWDPI_DBG("2 - run signature from %s\n", path);
		chdir(TMP_BWDPI);
		eval(AGENT, "-g", "-r", path);
		chdir("/");
	}

final:
	// step3. check signature exist or not
	if (!f_exists(APPDB) || !f_exists(CATDB) || !f_exists(RULEV)) {
		path = "/usr/bwdpi/rule.trf";
		BWDPI_DBG("3 - run signature from %s\n", path);
		chdir(TMP_BWDPI);
		eval(AGENT, "-g", "-r", path);
		chdir("/");
	}
}

void start_tm_qos()
{
	char dev_wan[128] = {0};
	char cmd[256] = {0};
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

	/* only support SW_MODE_ROUTER mode*/
	//if (!is_router_mode())
	//	return;

	if (!f_exists(TMP_BWDPI))
		mkdir(TMP_BWDPI, 0666);

	// step1. create dev node
	if (!f_exists("/dev/detector"))
		eval("mknod", "/dev/detector", "c", "190", "0");
	if (!f_exists("/dev/idpfw"))
		eval("mknod", "/dev/idpfw", "c", "191", "0");

	// step2. setup iptables rules
	eval("iptables", "-t", "mangle", "-N", "BWDPI_FILTER");
	eval("iptables", "-t", "mangle", "-F", "BWDPI_FILTER");
	eval("iptables", "-t", "mangle", "-A", "BWDPI_FILTER", "-i", dev_wan, "-p", "udp", "--sport", "68", "--dport", "67", "-j", "DROP");
	eval("iptables", "-t", "mangle", "-A", "BWDPI_FILTER", "-i", dev_wan, "-p", "udp", "--sport", "67", "--dport", "68", "-j", "DROP");
	eval("iptables", "-t", "mangle", "-A", "PREROUTING", "-i", dev_wan, "-p", "udp", "-j", "BWDPI_FILTER");

	// step3. insert DPI engine
	snprintf(cmd, sizeof(cmd),"insmod %s 2>/dev/null", TDTS);
	system(cmd);

	// step4. run bwdpi-rule-agent
	run_signature_check();

	// step5. insert UDB and Forward module
	if (!strcmp(dev_wan, ""))
		strlcpy(dev_wan, "nas0", sizeof(dev_wan));

	// step6. special case for low memory models
	// TODO : if found some models with low memory, need to adjust the parameters
	int sess = 30000;
	snprintf(cmd, sizeof(cmd),"insmod %s dev_wan=%s qos_wan=%s qos_lan=%s sess_num=%d user_timeout=3600 app_timeout=3600 2>/dev/null", UDB, dev_wan, dev_wan, nvram_safe_get("lan_ifname"), sess);
	system(cmd);
	snprintf(cmd, sizeof(cmd),"insmod %s 2>/dev/null", UDBFW);
	system(cmd);

	// step6. chmod 644 for parameters
	eval("chmod", "0644", TDTSFW_PARA, "-R");
}

int tm_qos_main(char *cmd)
{
	if (!strcmp(cmd, "restart")) {
		stop_tm_qos();
		start_tm_qos();
	}
	else if (!strcmp(cmd, "stop")) {
		stop_tm_qos();
	}
	else if (!strcmp(cmd, "start")) {
		start_tm_qos();
	}
	return 1;
}

void stop_qosd()
{
	FILE *fd = NULL;
	char buf[128], tcd_pid_tmp[10];
	int tcd_pid = 0;

	// set qos off
	int ret = doSystem("%s -a set_qos_off", SHN_CTRL);
	BWDPI_DBG("set_qos_off, ret=%d\n", ret);
	sleep(1);
	//doSystem("tc class show dev br0 classid 1:1");

	// kill tcd
	snprintf(buf, sizeof(buf), "pidof %s > /tmp/tcd.pid", TCD);
	system(buf);
	fd = fopen("/tmp/tcd.pid", "r");
	if (fd != NULL) {
		fgets(tcd_pid_tmp, sizeof(tcd_pid_tmp), fd);
		fclose(fd);
		system("rm -r /tmp/tcd.pid");
		tcd_pid = atoi(tcd_pid_tmp);
		if (tcd_pid != 0) {
			char cmd[256] = {0};
			snprintf(cmd, sizeof(cmd),"killall -9 %s 2>/dev/null", TCD);
			system(cmd);
		}
	}
}

void start_qosd()
{
	/* only support SW_MODE_ROUTER mode*/
	//if (!is_router_mode())
	//	return;

	if (nvram_get_int("qos_enable") == 0 || nvram_get_int("qos_type") == 0) {
		BWDPI_DBG("Adaptive QoS is disabled!!\n");
		return;
	}

	if (check_daulwan_mode() == 0) {
		BWDPI_DBG("Adaptive QoS doesn't support load-balance mode!\n");
		return;
	}

	if (!f_exists(TMP_BWDPI))
		mkdir(TMP_BWDPI, 0666);

	// step1. check dpi module
	if (dpi_module_check() == 0) {
		BWDPI_DBG("DPI engine module doesn't exist!!\n");
		return;
	}

	// step2. setup QOS_CONF
	setup_qos_conf();

	// step3. read conf via ioctl
	int ret = 0;
	ret = doSystem("%s -a set_qos_conf -R %s", SHN_CTRL, QOS_CONF);
	BWDPI_DBG("set_qos_conf, ret=%d\n", ret);

	// step4. run tcd daemon
	char *cmd1[] = {TCD, NULL};
	int pid;
	FILE *fd = NULL;
	char buf[128], tcd_pid_tmp[10];
	int tcd_pid = 0;
	snprintf(buf, sizeof(buf), "pidof %s > /tmp/tcd.pid", TCD);
	system(buf);
	fd = fopen("/tmp/tcd.pid", "r");
	if (fd != NULL) {
		fgets(tcd_pid_tmp, sizeof(tcd_pid_tmp), fd);
		fclose(fd);
		system("rm -r /tmp/tcd.pid");
		tcd_pid = atoi(tcd_pid_tmp);
		if (tcd_pid == 0) {
			_eval(cmd1, "/dev/null", 0, &pid);
		}
	}

	// step5. set qos on
	ret = doSystem("%s -a set_qos_on", SHN_CTRL);
	sleep(3); // need to sleep a while
	BWDPI_DBG("set_qos_on, ret=%d\n", ret);
	//doSystem("tc class show dev br0 classid 1:1");

	// step6. get dev_wan and setup parameter
	char dev_wan[16];
	memset(dev_wan, 0, sizeof(dev_wan));
	check_qosd_wan_setting(dev_wan, sizeof(dev_wan));
	f_write_string(QOS_WAN, dev_wan, 0, 0);
	BWDPI_DBG("dev_wan=%s, path=%s\n", dev_wan, QOS_WAN);
}

void restart_qosd()
{
	stop_qosd();
	start_qosd();
}

int qosd_main(char *cmd)
{
	if (!strcmp(cmd, "restart")) {
		stop_qosd();
		start_qosd();
	}
	else if (!strcmp(cmd, "stop")) {
		stop_qosd();
	}
	else if (!strcmp(cmd, "start")) {
		start_qosd();
	}
	return 1;
}
