/*
	wrs.c for TrendMicro WRS (parental control)
*/

#include "bwdpi.h"
//#include <bcmnvram.h>
#ifdef RTCONFIG_PERMISSION_MANAGEMENT
#include <PMS_DBAPIs.h>
#endif

static int global_wrs = 0; // check wrs all clients setting

cid_s *initial_id(cid_s **target_list)
{
	cid_s *tmp_id;

	if (target_list == NULL)
		return NULL;

	*target_list = (cid_s *)malloc(sizeof(cid_s));
	if (*target_list == NULL)
		return NULL;

	tmp_id = *target_list;

	tmp_id->id = 0;
	tmp_id->next = NULL;

	return tmp_id;
}

void free_id_list(cid_s **target_list)
{
	cid_s *tmp_id, *old_id;

	if (target_list == NULL)
		return;

	tmp_id = *target_list;
	while (tmp_id != NULL) {
		old_id = tmp_id;
		tmp_id = tmp_id->next;
		free(old_id);
	}

	return;
}

cid_s *get_id_list(cid_s **target_list, char *target_string)
{
	char word[4096], *next_word;
	cid_s **follow_id_list;

	if (target_list == NULL || target_string == NULL)
		return NULL;

	follow_id_list = target_list;
	while (*follow_id_list != NULL)
		follow_id_list = &((*follow_id_list)->next);

	foreach_44(word, target_string, next_word){
		if (initial_id(follow_id_list) == NULL) {
			printf("No memory!!(follow_id_list)\n");
			continue;
		}

		(*follow_id_list)->id = atoi(word);

		while (*follow_id_list != NULL)
			follow_id_list = &((*follow_id_list)->next);
	}

	return *target_list;
}

void print_id_list(cid_s *id_list)
{
	cid_s *follow_id;
	int i;

	if (id_list == NULL)
		return;

	i = 0;
	for (follow_id = id_list; follow_id != NULL; follow_id = follow_id->next) {
		++i;
		printf("      %3dth id: %d.\n", i, follow_id->id);
		if (follow_id->next != NULL)
			printf("------------------------------\n");
	}
}

cid_s *cp_id(cid_s **dest, const cid_s *src)
{
	if (initial_id(dest) == NULL) {
		printf("No memory!!(dest)\n");
		return NULL;
	}

	(*dest)->id = src->id;

	return *dest;
}

wrs_s *initial_wrs(wrs_s **target_list)
{
	wrs_s *tmp_wrs;

	if (target_list == NULL)
		return NULL;

	*target_list = (wrs_s *)malloc(sizeof(wrs_s));
	if (*target_list == NULL)
		return NULL;

	tmp_wrs = *target_list;

	tmp_wrs->enabled = 0;
	memset(tmp_wrs->mac, 0, 18);
	tmp_wrs->ids = NULL;
	tmp_wrs->next = NULL;

	return tmp_wrs;
}

void free_wrs_list(wrs_s **target_list)
{
	wrs_s *tmp_wrs, *old_wrs;

	if (target_list == NULL)
		return;

	tmp_wrs = *target_list;
	while (tmp_wrs != NULL) {
		free_id_list(&(tmp_wrs->ids));

		old_wrs = tmp_wrs;
		tmp_wrs = tmp_wrs->next;
		free(old_wrs);
	}

	return;
}

wrs_s *get_all_wrs_list(wrs_s **wrs_list, char *setting_string){
	char word[4096], *next_word;
	char word2[4096], *next_word2;
	wrs_s *follow_wrs, **follow_wrs_list;
	int i;

	if (wrs_list == NULL)
		return NULL;

	follow_wrs_list = wrs_list;
	foreach_60(word, setting_string, next_word) {
		if (initial_wrs(follow_wrs_list) == NULL) {
			printf("No memory!!(follow_wrs_list)\n");
			continue;
		}

		if (strlen(word) > 0) {
			follow_wrs = *follow_wrs_list;
			i = 0;
			foreach_62(word2, word, next_word2) {
				switch (i) {
					case 0: // switch
						follow_wrs->enabled = atoi(word2);
						break;
					case 1: // MAC
						strlcpy(follow_wrs->mac, word2, 18);
						break;
					/*
						wrs: Adult>Communication>Security>Network
						app filter: Commercial>IM>P2P>Network>Streaming>Tunneling>Web
					*/
					default:
						get_id_list(&(follow_wrs->ids), word2);
						break;
				}

				++i;
			}
		}

		while (*follow_wrs_list != NULL)
			follow_wrs_list = &((*follow_wrs_list)->next);
	}

	return *wrs_list;
}

void print_wrs_list(wrs_s *wrs_list)
{
	wrs_s *follow_wrs;
	int i;

	if (wrs_list == NULL)
		return;

	i = 0;
	for (follow_wrs = wrs_list; follow_wrs != NULL; follow_wrs = follow_wrs->next) {
		++i;
		printf("*** %3dth rule:\n", i);
		printf("   enabled: %d.\n", follow_wrs->enabled);
		printf("       mac: %s.\n", follow_wrs->mac);
		print_id_list(follow_wrs->ids);
		printf("******************************\n");
	}
}

wrs_s *cp_wrs(wrs_s **dest, const wrs_s *src) {
	cid_s *follow_id, **follow_id_list;

	if (initial_wrs(dest) == NULL) {
		printf("No memory!!(dest)\n");
		return NULL;
	}

	(*dest)->enabled = src->enabled;
	strcpy((*dest)->mac, src->mac);

	follow_id_list = &((*dest)->ids);
	for (follow_id = src->ids; follow_id != NULL; follow_id = follow_id->next) {
		cp_id(follow_id_list, follow_id);

		while (*follow_id_list != NULL)
			follow_id_list = &((*follow_id_list)->next);
	}

	return *dest;
}

wrs_s *match_enabled_wrs_list(wrs_s *wrs_list, wrs_s **target_list, int enabled)
{
	wrs_s *follow_wrs, **follow_target_list;

	if (wrs_list == NULL || target_list == NULL)
		return NULL;

	if (enabled != 0 && enabled != 1)
		return NULL;

	follow_target_list = target_list;
	for (follow_wrs = wrs_list; follow_wrs != NULL; follow_wrs = follow_wrs->next) {
		if (follow_wrs->enabled == enabled)
		{
			cp_wrs(follow_target_list, follow_wrs);

			while (*follow_target_list != NULL)
				follow_target_list = &((*follow_target_list)->next);
		}
	}

	return *target_list;
}

mac_s *initial_mac(mac_s **target_list)
{
	mac_s *tmp_mac;

	if (target_list == NULL)
		return NULL;

	*target_list = (mac_s *)malloc(sizeof(mac_s));
	if (*target_list == NULL)
		return NULL;

	tmp_mac = *target_list;

	memset(tmp_mac->mac, 0, 18);
	tmp_mac->next = NULL;

	return tmp_mac;
}

void free_mac_list(mac_s **target_list)
{
	mac_s *tmp_mac, *old_mac;

	if (target_list == NULL)
		return;

	tmp_mac = *target_list;
	while (tmp_mac != NULL) {
		old_mac = tmp_mac;
		tmp_mac = tmp_mac->next;
		free(old_mac);
	}

	return;
}

mac_s *get_mac_list(mac_s **target_list, const char *target_string)
{
	mac_s **follow_mac_list;

	if (target_list == NULL || target_string == NULL)
		return NULL;

	follow_mac_list = target_list;
	while (*follow_mac_list != NULL)
		follow_mac_list = &((*follow_mac_list)->next);

	if (initial_mac(follow_mac_list) == NULL) {
		printf("No memory!!(follow_mac_list)\n");
		return NULL;
	}

	strlcpy((*follow_mac_list)->mac, target_string, 18);

	return *target_list;
}

void print_mac_list(mac_s *mac_list)
{
	mac_s *follow_mac;
	int i;

	if (mac_list == NULL)
		return;

	i = 0;
	for (follow_mac = mac_list; follow_mac != NULL; follow_mac = follow_mac->next) {
		++i;
		printf("      %3dth mac: %s.\n", i, follow_mac->mac);
		if (follow_mac->next != NULL)
			printf("------------------------------\n");
	}
}

mac_g *initial_group_mac(mac_g **target_list)
{
	mac_g *tmp_group;

	if (target_list == NULL)
		return NULL;

	*target_list = (mac_g *)malloc(sizeof(mac_g));
	if (*target_list == NULL)
		return NULL;

	tmp_group = *target_list;

	memset(tmp_group->group_name, 0, 18);
	tmp_group->macs = NULL;

	return tmp_group;
}

void free_group_mac(mac_g **target)
{
	mac_g *tmp_group;

	if (target == NULL || *target == NULL)
		return;

	tmp_group = *target;
	free_mac_list(&(tmp_group->macs));
	free(tmp_group);

	return;
}

#ifdef RTCONFIG_PERMISSION_MANAGEMENT
mac_g *get_group_mac(mac_g **mac_group, const char *target)
{
	int dev_num, group_num;
	PMS_DEVICE_INFO_T *dev_list = NULL;
	PMS_DEVICE_GROUP_INFO_T *group_list = NULL, *follow_group = NULL;
	mac_g *follow_mac = NULL;

	if (mac_group == NULL) return NULL;
	
	/* Get account / group list */
	if (PMS_GetDeviceInfo(PMS_ACTION_GET_FULL, &dev_list, &group_list, &dev_num, &group_num) < 0) {
		printf("Can't read dev / group list\n");
		return NULL;
	}

	/* Get the mac list of certain group */
	for (follow_group = group_list; follow_group != NULL; follow_group = follow_group->next) {
		if (!strcmp(follow_group->name, target)) {
			if(initial_group_mac(mac_group) == NULL){
				printf("No memory!!(mac_group)\n");
				return NULL;
			}

			follow_mac = *mac_group;
			snprintf(follow_mac->group_name, 128, "%s", follow_group->name);

			PMS_OWNED_INFO_T *owned_dev = follow_group->owned_device;
			while (owned_dev != NULL) {
				PMS_DEVICE_INFO_T *dev_owned = (PMS_DEVICE_INFO_T *) owned_dev->member;
				get_mac_list(&(follow_mac->macs), dev_owned->mac);
				//printf("[%s] %s\n", follow_group->name, dev_owned->mac); // debug
				owned_dev = owned_dev->next;
			}
		}
	}

	/* Free device and group list*/
	PMS_FreeDevInfo(&dev_list, &group_list);

	return follow_mac;
}
#else
mac_g *get_group_mac(mac_g **mac_group, const char *target){
	char nvram_value[PATH_MAX];
	char word[4096], *next_word;
	char word2[4096], *next_word2;
	mac_g *follow_mac = NULL;
	int i = 0;

	if (mac_group == NULL)
		return NULL;

	snprintf(nvram_value, PATH_MAX, "%s", nvram_safe_get("wrs_group"));

	foreach_60(word, nvram_value, next_word) {
		foreach_62(word2, word, next_word2) {
			switch (i) {
				case 0: // Group name
					if(strcmp(target, word2))
						goto next_group;
					else{
						if(initial_group_mac(mac_group) == NULL) {
							printf("No memory!!(mac_group)\n");
							return NULL;
						}

						follow_mac = *mac_group;
						snprintf(follow_mac->group_name, 128, "%s", word2);
					}
					break;
				default: // MAC list
					get_mac_list(&(follow_mac->macs), word2);
					break;
			}
			++i;
		}

next_group:
		i = 0;
	}

	return follow_mac;
}
#endif

void print_group_mac(mac_g *mac_group)
{
	if (mac_group == NULL)
		return;

	printf("        group: %s.\n", mac_group->group_name);
	print_mac_list(mac_group->macs);
	printf("******************************\n");
}

/*
	erase_symbol : erase some specific symbol from string
	ex. 
	MAC=00:11:22:33:44:55 
	After using erase_symbol(MAC, ":")
	MAC=001122334455

	old : mac format
	sym : symbol

*/
void erase_symbol(char *old, char *sym)
{
	char buf[20];
	int strLen;

	char *FindPos = strstr(old, sym);
	if ((!FindPos) || (!sym)) {
		return;
	}

	// add protection of mac size
	if (strlen(old) > (sizeof(buf) - 1)) {
		return;
	}

	while (FindPos != NULL) {
		//dbg("FindPos=%s, old=%s\n", FindPos, old);
		memset(buf, 0, sizeof(buf));
		strLen = FindPos - old;
		strncpy(buf, old, strLen);
		strcat(buf, FindPos+1);
		strcpy(old, buf);
		FindPos = strstr(old, sym);
	}
	
	//dbg("macaddr=%s\n", old);
}

void output_wrs_block(FILE *fp, char *mac, cid_s *ids)
{
	cid_s *follow_id;

	if (!strcasecmp(mac, "all"))
		global_wrs = 1;
	else
		global_wrs = 0;

	if (global_wrs) {
		BWDPI_DBG("set ALL clients\n");
		fprintf(fp, "\nenable_default_rule=%d\n", global_wrs);
	}
	else {
		BWDPI_DBG("set EACH clients\n");
		erase_symbol(mac, ":");
		fprintf(fp, "mac=%s\n", mac);
	}

	for (follow_id = ids; follow_id != NULL; follow_id = follow_id->next)
		fprintf(fp, "catid=%d\n", follow_id->id);

}

void setup_wrs_conf()
{
	FILE *fp;
	wrs_s *wrs_list = NULL, *enabled_list = NULL, *follow_wrs;
	mac_g *mac_group;
	mac_s *follow_mac;

	if (!f_exists(TMP_BWDPI))
		mkdir(TMP_BWDPI, 0666);

	if ((fp = fopen(WRS_CONF, "w")) == NULL) {
		printf("fail to open %s.\n", WRS_CONF);
		return;
	}

	if (nvram_get_int("wrs_enable") == 1)
	{
		get_all_wrs_list(&wrs_list, nvram_safe_get("wrs_rulelist"));
		match_enabled_wrs_list(wrs_list, &enabled_list, 1);
		free_wrs_list(&wrs_list);

		if (enabled_list != NULL)
			fprintf(fp, "\n");

		for (follow_wrs = enabled_list; follow_wrs != NULL; follow_wrs = follow_wrs->next) {
			if (follow_wrs->enabled == 0)
				continue;

			if (follow_wrs->mac[0] == '@') {
				get_group_mac(&mac_group, follow_wrs->mac+1);
				for (follow_mac = mac_group->macs; follow_mac != NULL; follow_mac = follow_mac->next) {
					//printf("%s, %s\n", mac_group->group_name, follow_mac->mac);
					output_wrs_block(fp, follow_mac->mac, follow_wrs->ids);
				}
			}
			else {
				output_wrs_block(fp, follow_wrs->mac, follow_wrs->ids);
			}

			if (follow_wrs->next != NULL)
				fprintf(fp, "\n");
		}

		free_wrs_list(&enabled_list);
	}

	// enable default rule
	fprintf(fp, "\nenable_default_rule=1\n");

	// for TrendMicro to redirect blocking page for showing the category id
	if (nvram_get_int("http_enable") == 0)
		fprintf(fp, "redirect_url=http://%s/blocking.htm\n", nvram_safe_get("lan_ipaddr"));
	else
		fprintf(fp, "redirect_url=https://%s:%s/blocking.htm\n", nvram_safe_get("lan_ipaddr"), nvram_safe_get("https_lanport"));

	fclose(fp);

	// execute command
	eval(WRED_SET, "-f", WRS_CONF);
}

void stop_wrs()
{
	system("killall -9 wred 2>/dev/null");
}

void start_wrs()
{
	char buf[256];
	FILE *fd = NULL;
	char wred_pid_tmp[10];
	int wred_pid = 0;

	/* only support SW_MODE_ROUTER mode*/
	//if (!is_router_mode())
	//	return;

	snprintf(buf, sizeof(buf), "pidof %s > /tmp/wred.pid", WRED);
	system(buf);
	fd = fopen("/tmp/wred.pid", "r");
	if (fd != NULL) {
		fgets(wred_pid_tmp, sizeof(wred_pid_tmp), fd);
		fclose(fd);
		system("rm -r /tmp/wred.pid");
		wred_pid = atoi(wred_pid_tmp);
		if (wred_pid == 0) {
			// cleanup wred
			stop_wrs();

			// in TMP_BWDPI, will produce wred.pid
			chdir(TMP_BWDPI);
			snprintf(buf, sizeof(buf), "LD_LIBRARY_PATH=%s %s -B &", TMP_BWDPI, WRED); // -B : background, -D : debug
			BWDPI_DBG("buf=%s\n", buf);
			system(buf);

			// create wred.conf
			setup_wrs_conf();
		}
	}
}

int wrs_main(char *cmd)
{
	if (!strcmp(cmd, "restart")) {
		stop_wrs();
		start_wrs();
	}
	else if (!strcmp(cmd, "stop")) {
		stop_wrs();
	}
	else if (!strcmp(cmd, "start")) {
		start_wrs();
	}
	return 1;
}
