#include <stdio.h>	//for fgets() and other file I/O
#include <stdlib.h>	//realloc(), free(), strtoul(),atoi()
#include <fcntl.h>	//File handling using open(), read(), write() and close()
#include <unistd.h>	//read(), close()
#include <string.h>	//strstr(), strlen(), memset()
#include <time.h>
#include <sys/stat.h>
#include <signal.h>
#include "bwdpi.h"

static int sig_cur = -1;
static int sig_alarm = 0;
static int sig_term = 0;
static void catch_sig(int sig)
{
	sig_cur = sig;

	if(sig == SIGALRM)
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
	FILE *fp = fopen("/var/run/check_sig_version.pid", "r");
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
		BWDPI_DBG("%s: check_sig_version is already running.\n", __FUNCTION__);
		return 0;
	}

	fp = fopen("/var/run/check_sig_version.pid", "w");
	if(fp != NULL){
		fprintf(fp, "%d", getpid());
		fclose(fp);
	}

	/* set the signal handler */
	sigemptyset(&sigs_to_catch);
	sigaddset(&sigs_to_catch, SIGALRM);
	sigaddset(&sigs_to_catch, SIGTERM);
	sigprocmask(SIG_UNBLOCK, &sigs_to_catch, NULL);

	signal(SIGALRM, catch_sig);
	signal(SIGTERM, catch_sig);

	while (1) {
		if (sig_cur == -1)
		{
			alarm(30);
		}
		if (sig_alarm == 1)
		{
			auto_sig_check();
			//AiProtectionMonitor_mail_log();
			tm_eula_check();
			alarm(30);
			sig_alarm = 0;
		}
		if (sig_term == 1)
		{
			exit(0);
		}

		pause();
	}
	return 0;
}