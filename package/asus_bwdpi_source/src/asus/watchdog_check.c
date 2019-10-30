/*
	watchdog_check.c for rc/watchdog.c
	purpose : built in shared library for avoiding third party porting
*/

#include "bwdpi.h"

#if 0
static int model_protection()
{
	// add model name here, it's closed-source
	int result = 0;
	int model = get_model();
	if (model == MODEL_RTAC56U
		|| model == MODEL_RTAC68U
		|| model == MODEL_RTAC87U
		|| model == MODEL_RTAC3200
		|| model == MODEL_DSLAC68U
		|| model == MODEL_RTAC88U
		|| model == MODEL_RTAC5300
		|| model == MODEL_RTAC3100
		|| model == MODEL_GTAC5300
		|| model == MODEL_RTAC86U
		|| model == MODEL_RTAC85U
#if defined(RTCONFIG_SOC_IPQ8064)
		|| model == MODEL_BRTAC828
#endif
#if defined(RTCONFIG_SOC_IPQ40XX)
		|| model == MODEL_MAPAC1300
		|| model == MODEL_MAPAC2200
		|| model == MODEL_VRZAC1300
#endif
#if defined(RTCONFIG_ALPINE)
		|| model == MODEL_GTAC9600
#endif
#if defined(RTCONFIG_LANTIQ)
		|| model == MODEL_BLUECAVE
#endif
	)
		result = 1;

	return result;
}
#endif

/*
	signature protection function
	1 : allowd
	0 : forbidden
*/
static int bwdpi_signature_protection()
{
	if (check_bwdpi_nvram_setting() == 0) return 0;

	char dpi[16];
	char sig[16];
	char *a = NULL, *b = NULL, *c = NULL;
	char *d = NULL, *e = NULL;
	int i = 0 ,j = 0, k = 0;
	int m = 0, n = 0;

	strlcpy(dpi, nvram_safe_get("bwdpi_dpi_ver"), sizeof(dpi));
	strlcpy(sig, nvram_safe_get("bwdpi_sig_ver"), sizeof(sig));

	BWSIG_DBG("signature protection starting!\n");

	// add model protection here
	#if 0
	if (model_protection() == 0) {
		BWSIG_DBG("NOT to support this model");
		return 0;
	}
	#endif

	if ((vstrsep(dpi, ".", &a, &b, &c)) != 3) {
		BWSIG_DBG("DPI engine version WRONG format\n");
		return 0;
	}

	if ((vstrsep(sig, ".", &d, &e)) != 2) {
		BWSIG_DBG("SIG version WRONG format\n");
		return 0;
	}

	i = atoi(a);
	j = atoi(b);
	k = atoi(c);
	m = atoi(d);
	n = atoi(e);

	BWSIG_DBG("i=%d, j=%d, k=%d, m=%d, n=%d\n", i, j, k , m, n);

	if (i == 0 && j == 0) {
		// kernel dependent version
		BWSIG_DBG("DEP module\n");
		if (m == 1)
			return 1;
		else {
			BWSIG_DBG("DEP module : NOT to support fullset signature\n");
			return 0;
		}
	}
	else if (i > 0 || j > 0) {
		// kernel independent version
		BWSIG_DBG("INDEP module\n");
		if (m > 1)
			return 1;
		else {
			BWSIG_DBG("DEP module : MUST use fullset signature\n");
			return 0;
		}
	}
	else {
		// do nothing
		BWSIG_DBG("engine version is ILLEGAL!!\n");
		return 0;
	}

	return 1;
}

int ntp_stat()
{
	int ret = 0;
	FILE *fp = NULL;
	char line[64] = "", sts[16] = "";

	if ((fp = fopen("/tmp/ntp_status", "r")) == NULL)
	{
		printf("%s", "Cannot open uptime file!\n");
		return -1;
	}

	if(fgets(line, sizeof(line), fp) != NULL )
	{
		sscanf(line, "get_time_state=%s", sts);
		ret = atoi(sts);
	}

	fclose(fp);

	return ret;
}

/*
	signature update via shell script
*/
void auto_sig_check()
{
	static int period = 190; //ASUSWRT: 5757s
	static int bootup_check = 1;
	static int periodic_check = 0;
	int cycle_manual = nvram_get_int("sig_check_period");
	int cycle = (cycle_manual > 1) ? cycle_manual : 192; //ASUSWRT: 5760s
	time_t now;
	struct tm *tm;

	// check ntp sync
	if (!ntp_stat())
	{
		BWSIG_DBG("NTP isn't ready\n");
		return;
	}

	BWSIG_DBG("period=%d, bootup_check=%d, periodic_check=%d\n", period, bootup_check, periodic_check);
	if (!bootup_check && !periodic_check)
	{
		time(&now);
		tm = localtime(&now);

		if ((tm->tm_hour == 2))	// every 24 hours at 2 am
		{
			periodic_check = 1;
			period = -1;
		}
	}

	if (bootup_check || periodic_check)
		period = (period + 1) % cycle;
	else
		return;

	if (!bwdpi_signature_protection()) {
		BWSIG_DBG("signature protection return 0\n");
		return;
	}

	if (!period)
	{
		if (bootup_check)
			bootup_check = 0;

		eval("/usr/sbin/sig2nd_update.sh");

		if (nvram_get_int("sig_state_update") &&
		    !nvram_get_int("sig_state_error") &&
		    strlen(nvram_safe_get("sig_state_info")))
		{
			BWSIG_DBG("retrieve sig information\n");

			if (!nvram_get_int("sig_state_flag"))
			{
				BWSIG_DBG("NOT need to upgrade signature\n");
				return;
			}

			nvram_set_int("auto_sig_upgrade", 1);

			eval("/usr/sbin/sig2nd_upgrade.sh");

			if (nvram_get_int("sig_state_error"))
			{
				BWSIG_DBG("FAIL to execute sig2nd_upgrade.sh\n");
				goto ERROR;
			}
		}
		else
			BWSIG_DBG("CAN'T retrieve sig information\n");
ERROR:
		nvram_set_int("auto_sig_upgrade", 0);
	}
}

#if 0
/*
	save web history database
*/
void web_history_save()
{
	static int period = 0;
	int cycle = 4;

	// step1. check web history enable or not
	if (nvram_get_int("bwdpi_wh_enable") == 0) {
		BWSQL_LOG("web history function disabled");
		return;
	}

	// step2. check ntp sync
	if (!ntp_stat()) {
		BWSQL_LOG("NTP isn't ready\n");
		return;
	}

	// step3. do cycle
	period = (period + 1) % cycle;

	// step4. save web history database
	if (!period)
	{
		eval("WebHistory", "-e");
		eval("WebHistory", "-s", "5120"); // restrict size to 5MB
		BWSQL_LOG("SAVE database");
	}
}
#endif

/*
	AiProetecion v2.0
*/
void AiProtectionMonitor_mail_log()
{
	static int period = 0;
	int cycle = 4; // 4*30 = 120 sec

	if (check_bwdpi_nvram_setting() == 0)
	{
		return ;
	}

	// step1. check ntp sync
	if (!ntp_stat())
	{
		BWMON_LOG("NTP isn't ready\n");
		return;
	}

	// step2. do cycle
	period = (period + 1) % cycle;

	// step3. save Mals / CC / IPS database
	if (check_wrs_switch() && nvram_get_int("wrs_mail_bit") && (!period))
	{
		char tt[16];
		time_t now;

		time(&now);
		snprintf(tt, sizeof(tt), "%lu", now);

		eval("AiProtectionMonitor", "-e");
		eval("AiProtectionMonitor", "-l", "-t", tt);
		eval("AiProtectionMonitor", "-s", "2048"); // restrict size to 2MB
		BWMON_LOG("Save database");
	}
}

void tm_eula_check()
{
	char *cmd[] = {"shn_ctrl", "-a", "set_eula_agreed", NULL};
	int pid;
	int count = 0;
	FILE *fd = NULL;
	char buf[128], dcd_pid_tmp[10];
	int dcd_pid = 0;

	int is_eula = nvram_get_int("TM_EULA");
	BWDPI_DBG("is_eula=%d\n", is_eula);

	if (check_bwdpi_nvram_setting() == 0) {
		return;
	}

	if (f_exists(DCD_EULA) || is_eula == 0) {
		return;
	}
	snprintf(buf, sizeof(buf), "pidof %s > /tmp/dcd.pid", DATACOLLD);
	system(buf);
	fd = fopen("/tmp/dcd.pid", "r");
	if (fd != NULL) {
		fgets(dcd_pid_tmp, sizeof(dcd_pid_tmp), fd);
		fclose(fd);
		system("rm -r /tmp/dcd.pid");
		dcd_pid = atoi(dcd_pid_tmp);
		if (dcd_pid == 0) {
			return;
		}
	}

	if (is_eula) {
		BWDPI_DBG("check eula ...\n");
		while (count < 3) {
			BWDPI_DBG("count=%d\n", count);
			_eval(cmd, NULL, 0, &pid);
			BWDPI_DBG("set_eula_agreed ...\n");
			sleep(1);
			count++;
			if (f_exists(DCD_EULA)) break;
			if (count == 3) break;
		}
	}
}