#define WEBHISTORY_PATH		"/tmp/web_history_list"		/* temporary data file */
#define WEBHISTORY_UI_PATH	"/tmp/web_history.txt"		/* temporary file for UI display */
#define WEBHISTORY_DIR		"web_history_backup"
#define ROUTER_TMP_DIR		"router_temp"

/* webhistory save the maximum number of completed data */
#define MAXAL_LAN_CACHE		512
/* every AL_ALAM_CLOCK sec trigger webhistory daemon once */
#define WH_ALAM_CLOCK		15
/* at least tmie to backup Web History data */
#define LEAST_WH_BKP		60

#define DEBUG_WEB_HISTORY

#ifdef DEBUG_WEB_HISTORY
#define wh_dbg(fmt, args...) do { \
					FILE *fp = fopen("/tmp/web_history.log", "a"); \
					if (fp) { \
						fprintf(fp, fmt, ## args); \
						fclose(fp); \
					} \
				} while (0)
#else
#define wh_dbg(args...)	do { } while(0)
#endif

