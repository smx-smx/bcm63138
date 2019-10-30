#include <stdio.h>	//for fgets() and other file I/O
#include <stdlib.h>	//realloc(), free(), strtoul(),atoi()
#include <fcntl.h>	//File handling using open(), read(), write() and close()
#include <unistd.h>	//read(), close()
#include <string.h>	//strstr(), strlen(), memset()
#include <time.h>
#include <sys/stat.h>
#include <signal.h>
#include "asus_nvram.h"
#include "webhistory.h"

#define FAIL -1
#define SUCCESS 0

typedef struct clientInfo_s
{
	char ipaddr[64];
	char mac[32];
}clientInfo_t;
clientInfo_t landev[MAXAL_LAN_CACHE];

char *fd2str(int fd);
char *file2str(const char *path);
void StampToDate(unsigned long timestamp, char *date);
int ipSearchMac(char *ipaddr, char *macaddr, int macsize);
int gen_webHistory_file(void);
int backup_webhistory(void);
void check_to_backup(void);
static void catch_sig(int sig);

/*
 * Reads file and returns contents
 * @param	fd	file descriptor
 * @return	contents of file or NULL if an error occurred
 */
char *
fd2str(int fd)
{
	char *buf = NULL;
	size_t count = 0, n;

	do {
		buf = realloc(buf, count + 512);
		n = read(fd, buf + count, 512);
		if (n < 0) {
			free(buf);
			buf = NULL;
		}
		count += n;
	} while (n == 512);

	close(fd);
	if (buf)
		buf[count] = '\0';
	return buf;
}

/*
 * Reads file and returns contents
 * @param	path	path to file
 * @return	contents of file or NULL if an error occurred
 */
char *
file2str(const char *path)
{
	int fd;

	if ((fd = open(path, O_RDONLY)) == -1) {
		perror(path);
		return NULL;
	}

	return fd2str(fd);
}

void StampToDate(unsigned long timestamp, char *date)
{
	struct tm *local;
	time_t now;

	now = timestamp;
	local = localtime(&now);
	strftime(date, 30, "%Y-%m-%d %H:%M:%S", local);
}

int ipSearchMac(char *ipaddr, char *macaddr, int macsize)
{
	FILE *fp=NULL;
	char s[512], addr[32], hwaddr[32];
	char *p = NULL;

	if((fp = popen("mapi_common-net_lanhs_cli br0 get_host 0", "r")) != NULL) {
		while(fgets(s, sizeof(s), fp)) {
			if((p = strstr(s, "] ")) != NULL) {
				p += strlen("] ");
				sscanf(p, "%17s", hwaddr);

				if((p = strstr(s, "ip4=")) != NULL) {
					p += strlen("ip4=");
					sscanf(p, "%15s", addr);
					if (addr[strlen(addr)-1] == ',')
						addr[strlen(addr)-1] = '\0';

					if(strcmp(ipaddr, addr) == 0){
						snprintf(macaddr, macsize, "%s", hwaddr);
						pclose(fp);
						return SUCCESS;
					}
				}
			}
		}
		pclose(fp);
		wh_dbg("%s: no MAC info, ip = %s\n", __FUNCTION__, ipaddr);
	}
	return FAIL;
}

int gen_webHistory_file(void)
{
	FILE *fp=NULL, *f=NULL;
	char s[512], ip[64], mac[32], val[256];
	char date[30];
	unsigned long timestamp = 0;
	int i = 0, find = 0;

	fp = fopen(WEBHISTORY_PATH, "w");
	if(fp)
	{
		//wh_dbg("%s: start to wtire\n", __FUNCTION__);
		fprintf(fp, "Access Time\t\tIP Address\tMAC Address\t\tDomain Name\r\n");
		if ((f = fopen("/proc/webmon_recent_domains", "r")) != NULL) {
			while(fgets(s, sizeof(s), f)) {
				find = 0;
				memset(ip, 0, sizeof(ip));
				memset(val, 0, sizeof(val));
				if(sscanf(s, "%lu\t\t%63s\t%255s", &timestamp, ip, val) != 3) continue;
				for(i=0; i<MAXAL_LAN_CACHE; i++)
				{
					if(strlen(landev[i].ipaddr) == 0) break;
					if(strcmp(ip, landev[i].ipaddr) == 0){
						snprintf(mac, sizeof(mac), "%s", landev[i].mac);
						find = 1;
						//wh_dbg("%s: found, landev[%d].ipaddr=%s\n", __FUNCTION__, i, landev[i].ipaddr);
						break;
					}
				}
				if(find == 0) {
					memset(mac, 0, sizeof(mac));
					if(ipSearchMac(ip, mac, sizeof(mac)))
					{
						i = i % 512; //more than 512, it'll re-start
						snprintf(landev[i].ipaddr, sizeof(landev[i].ipaddr), "%s", ip);
						snprintf(landev[i].mac, sizeof(landev[i].mac), "%s", mac);
						//wh_dbg("%s: Add new record, landev[%d].ipaddr=%s, landev[%d].mac=%s\n", __FUNCTION__, i, landev[i].ipaddr, i, landev[i].mac);
					}
				}
				memset(date, 0, sizeof(date));
				StampToDate(timestamp, date);
				if(strlen(mac))
					fprintf(fp, "%s\t%s\t%s\t%s\r\n", date, ip, mac, val);
				else
					fprintf(fp, "%s\t%s\t%s\t\t%s\r\n", date, ip, ip, val);
			}
			fclose(f);
		}
		else {
			wh_dbg("%s: cannot open /proc/webmon_recent_domains\n", __FUNCTION__);
			return FAIL;
		}
		fclose(fp);
	}
	else {
		wh_dbg("%s: cannot write %s\n", __FUNCTION__, WEBHISTORY_PATH);
		return FAIL;
	}
	wh_dbg("%s: gen %s complete\n", __FUNCTION__, WEBHISTORY_PATH);
	return SUCCESS;
}

int backup_webhistory(void)
{
	char mnt_dir[48], log_path[128], log_dir[64], tmp[64], cmd[128];
	char hide_dir[64]={0}, nonhide_dir[64]={0};
	char *value = NULL;
	struct tm *local;
	time_t now;
	char date[30];

	value = nvram_get("wh_bkp_path");
	snprintf(mnt_dir, sizeof(mnt_dir), "/tmp/mnt/%s", value);
	if(!strlen(mnt_dir) || !check_if_dir_exist(mnt_dir)) {
		wh_dbg("%s: wh_bkp_path(%s) check failed\n", __FUNCTION__, mnt_dir);
		if(nvram_get_int("wh_bkp_path_fail") < 1)
			nvram_set("wh_bkp_path_fail", "1");
		return FAIL;
	}

	/* backup the web history into /.router_temp/web_history_backup/ folder in the USB */
	snprintf(hide_dir, sizeof(hide_dir), "%s/.%s", mnt_dir, ROUTER_TMP_DIR);
	snprintf(nonhide_dir, sizeof(nonhide_dir), "%s/%s", mnt_dir, ROUTER_TMP_DIR);
	memset(tmp, 0, sizeof(tmp));
	int log_bkp_nonhide = nvram_get_int("log_bkp_nonhide");
	if(log_bkp_nonhide == 0) {
		if(check_if_dir_exist(nonhide_dir) && !check_if_dir_exist(hide_dir)) {
			snprintf(cmd, sizeof(cmd), "mv %s %s", nonhide_dir, hide_dir);
			system(cmd);
		}
		snprintf(tmp, sizeof(tmp), "%s", hide_dir);
	}
	else {
		if(check_if_dir_exist(hide_dir) && !check_if_dir_exist(nonhide_dir)) {
			snprintf(cmd, sizeof(cmd), "mv %s %s", hide_dir, nonhide_dir);
			system(cmd);
		}
		snprintf(tmp, sizeof(tmp), "%s", nonhide_dir);
	}
	if(!check_if_dir_exist(tmp)) {
		if(mkdir(tmp, 0777)) {
			wh_dbg("%s: Create %s directory failed\n", __FUNCTION__, tmp);
			nvram_set("wh_bkp_path_fail", "1");
			return FAIL;
		}
	}
	memset(log_dir, 0, sizeof(log_dir));
	snprintf(log_dir, sizeof(log_dir), "%s/%s", tmp, WEBHISTORY_DIR);
	if(!check_if_dir_exist(log_dir)) {
		if(mkdir(log_dir, 0777)) {
			wh_dbg("%s: Create %s directory failed\n", __FUNCTION__, log_dir);
			nvram_set("wh_bkp_path_fail", "1");
			return FAIL;
		}
	}

	time(&now);
	local = localtime(&now);
	strftime(date, 30, "%Y%m%d_%H%M", local);
	snprintf(log_path, sizeof(log_path), "%s/%s.txt", log_dir, date);
	wh_dbg("%s: web history log path: %s\n", __FUNCTION__, log_path);

	if(gen_webHistory_file() == SUCCESS)
	{
		snprintf(cmd, sizeof(cmd), "cp %s %s", WEBHISTORY_PATH, log_path);
		system(cmd);

		/* Auto backup success, clear wh_bkp_path_fail */
		if(nvram_get_int("wh_bkp_path_fail") == 1)
			nvram_set("wh_bkp_path_fail", "0");

		if(nvram_match("wh_clear", "1") && check_if_file_exist(log_path))
		{
			/* clean old rule */
			system("iptables -t filter -F monitor 2>/dev/null");
			/* setup new rule */
			value = nvram_get("wh_max");
			if(((value = nvram_get("wh_max")) != NULL) && (strlen(value) > 0))
			{
				snprintf(cmd, sizeof(cmd), "iptables -t filter -A monitor -p tcp -m webhistory --max_domains %s --clear_search --clear_domain -j RETURN", value);
				system(cmd);
			}
			else
			{
				snprintf(cmd, sizeof(cmd), "iptables -t filter -A monitor -p tcp -m webhistory --max_domains 5000 --clear_search --clear_domain -j RETURN");
				system(cmd);
			}
		}
	}
	else {
		nvram_set("wh_bkp_path_fail", "1");
		return FAIL;
	}

	return SUCCESS;
}

void check_to_backup(void)
{
	static unsigned long wh_bkp_time = 0;
	int wh_bkp_period = LEAST_WH_BKP;
	char *ptr = NULL;

	if (nvram_match("wh_enable", "1") && nvram_match("wh_bkp_enable", "1"))
	{
		/* avoid the extra records at the beginning, %lu.%02lu %lu.%02lu in fs/proc/uptime.c */
		char *str = file2str("/proc/uptime");
		unsigned long up = strtoul(str, NULL, 0);
		free(str);

		/* the first time enter after reboot */
		if(wh_bkp_time == 0) {
			/* update the wh_bkp_time */
			wh_bkp_time = up;
			return;
		}

		/* every wh_bkp_period (sec) to backup Web History data */
		ptr = nvram_get("wh_bkp_period");
		wh_bkp_period = atoi(ptr);
		if(wh_bkp_period < LEAST_WH_BKP) {
			/* at least LEAST_WH_BKP(60) seconds */
			wh_bkp_period = LEAST_WH_BKP;
			nvram_set("wh_bkp_period", "60");
			wh_dbg("%s: at least %d seconds to backup Web History data\n", __FUNCTION__, LEAST_WH_BKP);
		}

		if((up-wh_bkp_time) >= wh_bkp_period)
		{
			wh_dbg("webhistory backup ...\n");
			if(backup_webhistory() != SUCCESS)
				wh_dbg("%s: webhistory backup fail\n", __FUNCTION__);

			/* update the wh_bkp_time */
			/* i.e. wh_bkp_time = up, but correct the error amount */
			wh_bkp_time = (((up/wh_bkp_period)*wh_bkp_period) + (wh_bkp_time%wh_bkp_period));
		}
	}
	else if(wh_bkp_time > 0) {
		/* disable web history or auto backup, reset backup time */
		wh_bkp_time = 0;
		wh_dbg("%s: clean wh_bkp_time\n", __FUNCTION__);
	}
}

static int sig_cur = -1;
static int sig_user1 = 0;
static int sig_alarm = 0;
static int sig_term = 0;
static void catch_sig(int sig)
{
	sig_cur = sig;

	if(sig == SIGUSR1)
	{
		sig_user1 = 1;
	}
	else if(sig == SIGALRM)
	{
		sig_alarm = 1;
	}
	else if(sig == SIGTERM)
	{
		sig_term = 1;
	}
}

int main(int argc, char *argv[])
{
	sigset_t sigs_to_catch;
	int pid = 0, flag = 0;
	char tmp[256];

	if(fork()) {
		exit(0);
	}
	setsid();

	flag = 0;
	FILE *fp = fopen("/var/run/webhistory.pid", "r");
	if(fp)
	{
		if(fscanf(fp, "%d", &pid) > 0)
		{
			sprintf(tmp, "/proc/%d", pid);
			if(!access(tmp, F_OK))
				flag = 1;
		}
		fclose(fp);
	}
	
	if(flag)
	{
		wh_dbg("%s: webhistory is already running.\n", __FUNCTION__);
		return 0;
	}

	fp = fopen("/var/run/webhistory.pid", "w");
	if(fp != NULL){
		fprintf(fp, "%d", getpid());
		fclose(fp);
	}

	/* set the signal handler */
	sigemptyset(&sigs_to_catch);
	sigaddset(&sigs_to_catch, SIGUSR1);
	sigaddset(&sigs_to_catch, SIGALRM);
	sigaddset(&sigs_to_catch, SIGTERM);
	sigprocmask(SIG_UNBLOCK, &sigs_to_catch, NULL);

	signal(SIGUSR1, catch_sig);
	signal(SIGALRM, catch_sig);
	signal(SIGTERM, catch_sig);

	while (1) {
		if (sig_cur == -1)
		{
			alarm(WH_ALAM_CLOCK);
		}
		if (sig_user1 == 1)
		{
			/* backup immediately after Apply */
			if(backup_webhistory() != SUCCESS)
				wh_dbg("%s: Web History backup fail\n", __FUNCTION__);
			sig_user1 = 0;
		}
		if (sig_alarm == 1)
		{
			check_to_backup();
			alarm(WH_ALAM_CLOCK);
			sig_alarm = 0;
		}
		if (sig_term == 1)
		{
			unlink(WEBHISTORY_PATH);
			unlink(WEBHISTORY_UI_PATH);
			exit(0);
		}

		pause();
	}
	return 0;
}
