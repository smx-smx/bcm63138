/*
	when traffic analyzer is enabled, bwdpi_db_10 will start to save database each minute, after 10 mins, it will be killed.
*/
#include <rc.h>
#include <bwdpi_common.h>

static int sig_cur = -1;
static int count = 0;

static void save_database_10()
{
	count++;

	BWSQL_DBG("count=%d\n", count);

	if(count >= 10){
		remove("/var/run/bwdpi_db_10.pid");
		exit(0);
	}
	else{
		hm_traffic_analyzer_save();
	}
}

static void catch_sig(int sig)
{
	sig_cur = sig;
	
	if(sig == SIGALRM)
	{
		BWSQL_DBG("check alive...\n");
		save_database_10();
	}
	else if (sig == SIGTERM)
	{
		BWSQL_DBG("KILL!!\n");
		remove("/var/run/bwdpi_db_10.pid");
		exit(0);
	}
}

int bwdpi_db_10_main(int argc, char **argv)
{
	FILE *fp;
	sigset_t sigs_to_catch;

	/* write pid */
	if ((fp = fopen("/var/run/bwdpi_db_10.pid", "w")) != NULL)
	{
		fprintf(fp, "%d", getpid());
		fclose(fp);
	}

	/* set the signal handler */
	sigemptyset(&sigs_to_catch);
	sigaddset(&sigs_to_catch, SIGTERM);
	sigaddset(&sigs_to_catch, SIGALRM);
	sigprocmask(SIG_UNBLOCK, &sigs_to_catch, NULL);

	signal(SIGTERM, catch_sig);
	signal(SIGALRM, catch_sig);

	while(1)
	{
		BWSQL_DBG("set alarm, count=%d\n", count);
		if(count <= 6) alarm(10);
		else if(count > 6) alarm(60);
		pause();
	}

	return 0;
}
