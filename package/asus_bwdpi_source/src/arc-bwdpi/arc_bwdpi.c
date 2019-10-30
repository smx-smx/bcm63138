#define cprintf(fmt, args...) do { \
	FILE *fp = fopen("/dev/console", "w"); \
	if (fp) { \
		fprintf(fp, fmt, ## args); \
		fclose(fp); \
	} \
} while (0)
#include<bwdpi_common.h>
#include<stdio.h>
#include<shared.h>
//#include<bwdpi.h>
int main(int argc, char **argv)
{
	
	cprintf("arc_bwdpi_deamon start\n"); 
	int enabled = check_bwdpi_nvram_setting(); 
	//BWDPI_DBG("enabled= %d\n", enabled);
	if(enabled)
	{
		//if restart_wan_if, remove dpi engine related 
		if(f_exists("/dev/detector") || f_exists("/dev/idpfw"))
		{
			cprintf("Stop dpi engine service\n"); 
			stop_dpi_engine_service(0); 
		} 
		cprintf("Start dpi engine service\n"); 
		start_dpi_engine_service(); 
	}
	return 1;

}
