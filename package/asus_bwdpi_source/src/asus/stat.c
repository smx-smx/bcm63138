/*
	stat.c for TrendMicro app parental control / application statistics / device statistics
*/

#include "bwdpi.h"

/*
	if status = all 		=> [TX, RX]
	if status = "" && name = ""	=> [[MAC0, TX, RX], [MAC1, TX, RX], ...]
	if status = "" && name = "MAC"	=> [[APP0, TX, RX], [APP1, TX, RX], ...]
*/
static void get_client_hook(struct request_rec *r, char *status, char *name)
{
	int ret = 0;
	int first_row = 1;
	unsigned int i, j, rec_max, rec_max2;
	unsigned long app_count = 0;
	unsigned long app_down = 0, app_up = 0;
	unsigned long total_down = 0, total_up = 0;
	udb_ioctl_entry_t *usr_lst = NULL;
	app_ioctl_entry_t *app_lst = NULL;
	uint32_t usr_buf_len = 0, app_buf_len = 0;
	char cat_name[64];
	char app_name[64];

	memset(cat_name, 0 , sizeof(cat_name));
	memset(app_name, 0 , sizeof(app_name));

	LIST_HEAD(app_inf_head);
	LIST_HEAD(app_cat_head);

	BWSQL_LOG("status=%s, name=%s", status, name);

	ret = get_fw_user_list(&usr_lst, &usr_buf_len);
	if (ret || !usr_lst) {
		printf("Error: get user!(%d)\n", ret);
	}

	ret = get_fw_user_app_rate(&app_lst, &app_buf_len);
	if (ret) {
		printf("Error: get app!(%d)\n", ret);
	}

	init_app_inf(&app_inf_head);
	init_app_cat(&app_cat_head);

	if (!strcmp(status, "")) {
		r->bytes_sent += so_printf(r, "[");
	}

	if (usr_lst) {
		rec_max = DEVID_MAX_USER;
		rec_max2 = DEVID_APP_RATE_TABLE_POOL_SIZE;

		total_down = total_up = 0;
		// each device
		for (i = 0; i < rec_max; i++)
		{
			char buff[18];
			if (usr_lst[i].available <= 0) break;

			app_down = app_up = app_count = 0;
			snprintf(buff, sizeof(buff), MAC_OCTET_FMT, MAC_OCTET_EXPAND(usr_lst[i].mac));

			if (!strcmp(status, "") && strcmp(name, "")) {
				// get certain client's app
				BWSQL_LOG("mac=%s, name=%s", buff, name);
				if (strcmp(buff, name)) continue;
				first_row = 1;

				for (j = 0; j < rec_max2; j++)
				{
					if (app_lst[j].available <= 0) break;
					if (usr_lst[i].uid == app_lst[j].uid)
					{
						if (app_lst[j].cat_id == 0 && app_lst[j].app_id == 0)
						{
							strlcpy(cat_name , "General", sizeof(cat_name));
							strlcpy(app_name , "General", sizeof(app_name));
						}
						else
						{
							char *cat = search_app_cat(&app_cat_head, app_lst[j].cat_id);
							char *inf = search_app_inf(&app_inf_head, app_lst[j].cat_id, app_lst[j].app_id);
							BWSQL_LOG("cat=%s, inf=%s", cat, inf);
							if (cat == NULL)
								strlcpy(cat_name , "General", sizeof(cat_name));
							else
								strlcpy(cat_name , cat, sizeof(cat_name));

							if (inf == NULL)
								strlcpy(app_name , "General", sizeof(app_name));
							else
								strlcpy(app_name , inf, sizeof(app_name));
						}

						BWSQL_LOG("[%5u] cat/app= %s/%s, cat/app id = %u/%u, up/down = %llu/%llu",
							j, cat_name, app_name, app_lst[j].cat_id, app_lst[j].app_id,
                                                        app_lst[j].up_recent_accl, app_lst[j].down_recent_accl);

						if (first_row == 1) {
							first_row = 0;
							r->bytes_sent += so_printf(r, "[\"%s\", \"%llu\", \"%llu\", \"%u\", \"%u\"]", 
									app_name, app_lst[j].up_recent_accl, app_lst[j].down_recent_accl,
									app_lst[j].cat_id, app_lst[j].app_id);
						}
						else {
							r->bytes_sent += so_printf(r, ", [\"%s\", \"%llu\", \"%llu\", \"%u\", \"%u\"]", 
									app_name, app_lst[j].up_recent_accl, app_lst[j].down_recent_accl,
									app_lst[j].cat_id, app_lst[j].app_id);
						}
						app_count++;
					}
				}
				if (!strcmp(buff, name)) break;
			}
			else {
				// each app in device
				for (j = 0; j < rec_max2; j++)
				{
					if (app_lst[j].available <= 0) break;
					if (usr_lst[i].uid == app_lst[j].uid)
					{
						app_down += app_lst[j].down_recent_accl;
						app_up += app_lst[j].up_recent_accl;
						app_count++;
					}
				}

				if (!strcmp(status, "all")) { // get all
					total_down += app_down;
					total_up += app_up;
					BWSQL_LOG("total_up/total_down=%lu/%lu", total_up, total_down);
				}
				else if (!strcmp(status, "") && !strcmp(name, "")) { // get each client
					if (i == 0)
						r->bytes_sent += so_printf(r, "[\"%s\", \"%lu\", \"%lu\"]", buff, app_up, app_down);
					else
						r->bytes_sent += so_printf(r, ", [\"%s\", \"%lu\", \"%lu\"]", buff, app_up, app_down);
					BWSQL_LOG("mac=%s, up/_down=%lu/%lu", buff, app_up, app_down);
				}
			}
		}
	}

	if (!strcmp(status, "")) {
		r->bytes_sent += so_printf(r, "]");
	}

	free_app_inf(&app_inf_head);
	free_app_cat(&app_cat_head);

	if (app_lst) free(app_lst);
	if (usr_lst) free(usr_lst);

	if (!strcmp(status, "all")) {
		r->bytes_sent += so_printf(r, "[\"%lu\", \"%lu\"]", total_up, total_down);
	}
}

static void get_traffic_client_stat(char *name)
{
	int ret = 0;
	int is_MAC = 0;
	unsigned int i, j, rec_max, rec_max2;
	unsigned long app_count = 0;
	unsigned long app_down = 0, app_up = 0;
	udb_ioctl_entry_t *usr_lst = NULL;
	app_ioctl_entry_t *app_lst = NULL;
	uint32_t usr_buf_len = 0, app_buf_len = 0;
	char cat_name[64];
	char app_name[64];

	memset(cat_name, 0 , sizeof(cat_name));
	memset(app_name, 0 , sizeof(app_name));

	LIST_HEAD(app_inf_head);
	LIST_HEAD(app_cat_head);

	if (name == NULL)
		is_MAC = 0;
	else
		is_MAC = 1;

	ret = get_fw_user_list(&usr_lst, &usr_buf_len);
	if (ret || !usr_lst) {
		printf("Error: get user!(%d)\n", ret);
	}

	ret = get_fw_user_app_rate(&app_lst, &app_buf_len);
	if(ret) {
		printf("Error: get app!(%d)\n", ret);
	}

	init_app_inf(&app_inf_head);
	init_app_cat(&app_cat_head);

	if (usr_lst) {
		rec_max = DEVID_MAX_USER;
		rec_max2 = DEVID_APP_RATE_TABLE_POOL_SIZE;

		// each device
		for (i = 0; i < rec_max; i++)
		{
			char buff[18];
			if (usr_lst[i].available <= 0) break;

			app_down = app_up = app_count = 0;
			snprintf(buff, sizeof(buff), MAC_OCTET_FMT, MAC_OCTET_EXPAND(usr_lst[i].mac));

			BWSQL_LOG("mac=%s, name=%s", buff, name);

			if (is_MAC) {
				if (strcmp(buff, name)) continue;
				for (j = 0; j < rec_max2; j++)
				{
					if (app_lst[j].available <= 0) break;
					if (usr_lst[i].uid == app_lst[j].uid)
					{
						if (app_lst[j].cat_id == 0 && app_lst[j].app_id == 0)
						{
							strlcpy(cat_name , "General", sizeof(cat_name));
							strlcpy(app_name , "General", sizeof(app_name));
						}
						else
						{
							char *cat = search_app_cat(&app_cat_head, app_lst[j].cat_id);
							char *inf = search_app_inf(&app_inf_head, app_lst[j].cat_id, app_lst[j].app_id);
							if (cat == NULL)
								strlcpy(cat_name , "General", sizeof(cat_name));
							else
								strlcpy(cat_name , cat, sizeof(cat_name));

							if (inf == NULL)
								strlcpy(app_name , "General", sizeof(app_name));
							else
								strlcpy(app_name , inf, sizeof(app_name));
						}

						BWSQL_LOG("[%5u] cat/app= %s/%s, cat/app id = %u/%u, up/down = %llu/%llu",
							j, cat_name, app_name, app_lst[j].cat_id, app_lst[j].app_id,
                                                        app_lst[j].up_recent_accl, app_lst[j].down_recent_accl);

						app_count++;
					}
				}
				if (!strcmp(buff, name)) break;
			}
			else {
				// each app in device
				for (j = 0; j < rec_max2; j++)
				{
					if (app_lst[j].available <= 0) break;

					if (usr_lst[i].uid == app_lst[j].uid)
					{
						app_down += app_lst[j].down_recent_accl;
						app_up += app_lst[j].up_recent_accl;
						app_count++;
					}
				}
				BWSQL_LOG("mac=%s, up/_down=%lu/%lu", buff, app_up, app_down);
			}
		}
	}

	free_app_inf(&app_inf_head);
	free_app_cat(&app_cat_head);

	if (app_lst) free(app_lst);
	if (usr_lst) free(usr_lst);
}

static void get_traffic_wan_stat()
{
	int ret = 0;
	unsigned int i, j, rec_max, rec_max2;
	unsigned long app_count = 0;
	unsigned long app_down = 0, app_up = 0;
	unsigned long total_down = 0, total_up = 0;
	udb_ioctl_entry_t *usr_lst = NULL;
	app_ioctl_entry_t *app_lst = NULL;
	uint32_t usr_buf_len = 0, app_buf_len = 0;

	ret = get_fw_user_list(&usr_lst, &usr_buf_len);
	if (ret || !usr_lst) {
		printf("Error: get user!(%d)\n", ret);
	}

	ret = get_fw_user_app_rate(&app_lst, &app_buf_len);
	if (ret) {
		printf("Error: get app!(%d)\n", ret);
	}

	if (usr_lst) {
		rec_max = DEVID_MAX_USER;
		rec_max2 = DEVID_APP_RATE_TABLE_POOL_SIZE;

		total_down = total_up = 0;
		// each device
		for (i = 0; i < rec_max; i++)
		{
			if (usr_lst[i].available <= 0) break;

			app_down = app_up = app_count = 0;

			// each app in device
			for (j = 0; j < rec_max2; j++)
			{
				if (app_lst[j].available <= 0) break;

				if (usr_lst[i].uid == app_lst[j].uid)
				{
					app_down += app_lst[j].down_recent_accl;
					app_up += app_lst[j].up_recent_accl;
					app_count++;
				}
			}

			total_down += app_down;
			total_up += app_up;
			BWSQL_LOG("total_up/total_down=%lu/%lu", total_up, total_down);
		}
	}

	if (app_lst) free(app_lst);
	if (usr_lst) free(usr_lst);
}

/*
	get_traffic_hook for web hook <% bwdpi_status() %>

	mode : traffic / traffic_wan / app / client_apps / client_web
	name : NULL / MAC / APP_NAME
	dura : realtime / month / week / day
	date : NULL / date
*/
#if 0
void get_traffic_hook(char *mode, char *name, char *dura, char *date, struct request_rec *r)
{
	BWSQL_LOG("mode=%s, name=%s, dura=%s, date=%s", mode, name, dura, date);

	// send singal to wake up to check bwdpi engine
	kill_pidfile_s("/var/run/bwdpi_check.pid", SIGUSR1);

	if (!strcasecmp(mode, "traffic_wan") && !strcasecmp(dura, "realtime")) {
		get_client_hook(r, "all", "");
	}
	else if (!strcasecmp(mode, "traffic") && !strcasecmp(dura, "realtime")) {
		get_client_hook(r, "", name);
	}
}
#endif

/*
	get_traffic_stat for binary bwdpi

	mode : traffic / traffic_wan / app / client_apps / client_web
	name : NULL / MAC / APP_NAME
	dura : realtime / month / week / day
	date : NULL / TIME
*/
void get_traffic_stat(char *mode, char *name, char *dura, char *date)
{
	BWSQL_LOG("mode=%s, name=%s, dura=%s, date=%s", mode, name, dura, date);

	if (!strcasecmp(mode, "traffic_wan") && !strcasecmp(dura, "realtime")) {
		get_traffic_wan_stat();
	}
	else if (!strcasecmp(mode, "traffic") && !strcasecmp(dura, "realtime")) {
		get_traffic_client_stat(name);
	}
	else{
		BWSQL_LOG("Others");
	}
}

int stat_main(char *mode, char *name, char *dura, char *date)
{
	if (!f_exists(TMP_BWDPI))
		mkdir(TMP_BWDPI, 0666);

	if (mode  == NULL || dura == NULL) {
		printf("You must input option mode(m) / dura(u), if lost any one, it can't output any information\n");
		return 0;
	}

	get_traffic_stat(mode, name, dura, date);

	return 1;
}

#if 0
void get_device_hook(char *MAC, struct request_rec *r)
{
	int ret = 0;
	unsigned int i, rec_max;
	udb_ioctl_entry_t *usr_lst = NULL;
	uint32_t usr_buf_len = 0;
	dev_os_t *dev_os;

	if (!strcmp(MAC, "")) MAC = "all";

	ret = get_fw_user_list(&usr_lst, &usr_buf_len);
	if (ret || !usr_lst) {
		printf("Error: get user!(%d)\n", ret);
	}

	LIST_HEAD(dev_os_head);
	init_dev_os(&dev_os_head);

	if (usr_lst) {
		r->bytes_sent += so_printf(r, "\"");
		rec_max = DEVID_MAX_USER;
		// each device
		for (i = 0; i < rec_max; i++)
		{
			char buff[18]; // MAC
			char buf[128]; // output buffer
			memset(buff, 0, sizeof(buff));
			memset(buf, 0, sizeof(buf));

			if (usr_lst[i].available <= 0) break;

			snprintf(buff, sizeof(buff), MAC_OCTET_FMT, MAC_OCTET_EXPAND(usr_lst[i].mac));
			BWSQL_DBG("%d MAC=%s\n", i, buff);

			if (strcmp(MAC, "all")) {
				if (strcmp(buff, MAC)) continue;
			}

			dev_os = search_dev_os(&dev_os_head,
				usr_lst[i].os.de.vendor_id,
				usr_lst[i].os.de.name_id,
				usr_lst[i].os.de.class_id,
				usr_lst[i].os.de.cat_id,
				usr_lst[i].os.de.dev_id,
				usr_lst[i].os.de.family_id);

			if (dev_os == NULL) {
				snprintf(buf, sizeof(buf), "&#60%s&#62%s&#62", buff, usr_lst[i].host_name);
			}
			else {
				snprintf(buf, sizeof(buf), "&#60%s&#62%s&#62%s&#62%s&#62%s", buff, usr_lst[i].host_name, dev_os->vendor_name, dev_os->type_name, dev_os->dev_name);
			}

			r->bytes_sent += so_printf(r, buf);

			if (strcmp(MAC, "all")) {
				if (!strcmp(buff, MAC)) break;
			}
		}
		r->bytes_sent += so_printf(r, "\"");
	}

	free_dev_os(&dev_os_head);

	if (usr_lst)
		free(usr_lst);
}
#endif

void get_device_stat(char *MAC)
{
	int ret = 0;
	int is_MAC = 0;
	unsigned int i, rec_max;
	udb_ioctl_entry_t *usr_lst = NULL;
	uint32_t usr_buf_len = 0;
	dev_os_t *dev_os;

	if (MAC == NULL)
		is_MAC = 0;
	else
		is_MAC = 1;

	ret = get_fw_user_list(&usr_lst, &usr_buf_len);
	if (ret || !usr_lst) {
		printf("Error: get user!(%d)\n", ret);
	}

	LIST_HEAD(dev_os_head);
	init_dev_os(&dev_os_head);

	if (usr_lst) {
		rec_max = DEVID_MAX_USER;
		// each device
		for (i = 0; i < rec_max; i++)
		{
			char buff[18];
			if (usr_lst[i].available <= 0) break;

			snprintf(buff, sizeof(buff), MAC_OCTET_FMT, MAC_OCTET_EXPAND(usr_lst[i].mac));

			if (is_MAC) {
				if (strcmp(buff, MAC)) continue;
				dev_os = search_dev_os(&dev_os_head,
					usr_lst[i].os.de.vendor_id,
					usr_lst[i].os.de.name_id,
					usr_lst[i].os.de.class_id,
					usr_lst[i].os.de.cat_id,
					usr_lst[i].os.de.dev_id,
					usr_lst[i].os.de.family_id);
				if (dev_os == NULL) BWSQL_DBG("%s>%s>NULL\n", buff, usr_lst[i].host_name);
				if (dev_os != NULL) BWSQL_DBG("%s>%s>%s>%s>%s\n", buff, usr_lst[i].host_name, dev_os->vendor_name, dev_os->type_name, dev_os->dev_name);
				if (!strcmp(buff, MAC)) break;
			}
			else{
				dev_os = search_dev_os(&dev_os_head,
					usr_lst[i].os.de.vendor_id,
					usr_lst[i].os.de.name_id,
					usr_lst[i].os.de.class_id,
					usr_lst[i].os.de.cat_id,
					usr_lst[i].os.de.dev_id,
					usr_lst[i].os.de.family_id);
				if (dev_os == NULL) BWSQL_DBG("%s>%s>NULL\n", buff, usr_lst[i].host_name);
				if (dev_os != NULL) BWSQL_DBG("%s>%s>%s>%s>%s\n", buff, usr_lst[i].host_name, dev_os->vendor_name, dev_os->type_name, dev_os->dev_name);
			}
		}
	}

	free_dev_os(&dev_os_head);

	if (usr_lst)
		free(usr_lst);
}

int device_main(char *MAC)
{
	get_device_stat(MAC);

	return 1;
}

/*
	bwdpi_client_info(char *MAC, bwdpi_device *device)
	input	: char *MAC
	output	: bwdpi_device *string
	For networkmap, use MAC to query hostname / vendor / type / device in dpi engine

	You can find struct "bwdpi_device" in bwdpi.h.
*/
int bwdpi_client_info(char *MAC, bwdpi_device *device)
{
	int ret = 0;
	unsigned int i, rec_max;
	udb_ioctl_entry_t *usr_lst = NULL;
	uint32_t usr_buf_len = 0;
	dev_os_t *dev_os;

	// initial
	memset(device->hostname, 0, sizeof(device->hostname));
	memset(device->vendor_name, 0, sizeof(device->vendor_name));
	memset(device->type_name, 0, sizeof(device->type_name));
	memset(device->device_name, 0, sizeof(device->device_name));

	if (MAC == NULL) {
		printf("host/vendor/type/device=%s/%s/%s/%s\n", device->hostname, device->vendor_name, device->type_name, device->device_name);
		return 0;
	}

	ret = get_fw_user_list(&usr_lst, &usr_buf_len);
	if (ret || !usr_lst) {
		printf("Error: get user!(%d)\n", ret);
		return 0;
	}

	LIST_HEAD(dev_os_head);
	init_dev_os(&dev_os_head);

	if (usr_lst) {
		rec_max = DEVID_MAX_USER;
		// each device
		for (i = 0; i < rec_max; i++)
		{
			char buff[18];
			if (usr_lst[i].available <= 0) break;

			snprintf(buff, sizeof(buff), MAC_OCTET_FMT, MAC_OCTET_EXPAND(usr_lst[i].mac));

			printf("buff=%s, MAC=%s\n", buff, MAC);
			if (strcmp(buff, MAC)) continue;
			dev_os = search_dev_os(&dev_os_head,
				usr_lst[i].os.de.vendor_id,
				usr_lst[i].os.de.name_id,
				usr_lst[i].os.de.class_id,
				usr_lst[i].os.de.cat_id,
				usr_lst[i].os.de.dev_id,
				usr_lst[i].os.de.family_id);
			if (dev_os == NULL) {
				strlcpy(device->hostname, usr_lst[i].host_name, sizeof(device->hostname));
			}
			else {
				strlcpy(device->hostname, usr_lst[i].host_name, sizeof(device->hostname));
				strlcpy(device->vendor_name, dev_os->vendor_name, sizeof(device->vendor_name));
				strlcpy(device->type_name, dev_os->type_name, sizeof(device->type_name));
				strlcpy(device->device_name, dev_os->dev_name, sizeof(device->device_name));
			}

			printf("host/vendor/type/device=%s/%s/%s/%s\n", device->hostname, device->vendor_name, device->type_name, device->device_name);
			if (!strcmp(buff, MAC)) break;
		}
	}

	free_dev_os(&dev_os_head);

	if (usr_lst)
		free(usr_lst);
	return 1;
}

int device_info_main(char *MAC)
{
	bwdpi_device *device;
	device = (bwdpi_device *)malloc(sizeof(bwdpi_device));
	bwdpi_client_info(MAC, device);
	free(device);

	return 1;
}

int _get_vp(int flag)
{
	int ret = 0;
	unsigned int ioc_buf;
	char *buf;

	//process ioctl request & response
	ret = get_fw_vp_list((void **) &buf, &ioc_buf);

	if (ret)
	{
		printf("Error: get user!(%d)\n", ret);
	}

	if (buf)
	{
		udb_vp_ioc_entry_t *ioc_ent;

		uint32_t tbl_used_len = 0, i = 0;
		uint32_t entry_cnt = ioc_buf / sizeof(udb_vp_ioc_entry_t);

		//workaround, prevent not memset
		if (entry_cnt > UDB_VIRTUAL_PATCH_LOG_SIZE)
		{
			entry_cnt = 0;
		}

		LIST_HEAD(rule_head);
		init_rule_db(&rule_head);

		printf("---entry_cnt = %u ---\n", entry_cnt);
		printf("---------------------------------\n");

		for (i = 0; i < entry_cnt; i++)
		{
			ioc_ent = (udb_vp_ioc_entry_t *) (buf + tbl_used_len);
			printf("---------------------------------\n");
			printf("[%i]mac: "MAC_OCTET_FMT"\n", i, MAC_OCTET_EXPAND(ioc_ent->mac));
			printf("\ttime: %llu\n", ioc_ent->btime);
			printf("\trule_id: %u\n", ioc_ent->rule_id);
			printf("\trule_name: %s\n", search_rule_db(&rule_head, ioc_ent->rule_id));
			printf("\thit_cnt: %d\n", ioc_ent->hit_cnt);
			printf("\trole: %s\n", ioc_ent->role == 1 ? "attacker" : "victim");
			printf("\tseverity: %u\n", ioc_ent->severity);
			printf("\tip_ver: %d\n", ioc_ent->ip_ver);
			printf("\tproto:  %d\n", ioc_ent->proto);
			printf("\tsport:  %d\n", ioc_ent->sport);
			printf("\tdport:  %d\n", ioc_ent->dport);
			printf("\taction:  %d-%s\n", ioc_ent->action, ioc_ent->action == 1 ? "Block" : (ioc_ent->action == 2) ? "Monitor" : "Accept");

			if (4 == ioc_ent->ip_ver)
			{
				printf("\tsip: "IPV4_OCTET_FMT"\n", IPV4_OCTET_EXPAND(ioc_ent->sip));
				printf("\tdip: "IPV4_OCTET_FMT"\n", IPV4_OCTET_EXPAND(ioc_ent->dip));
			}
			else if (6 == ioc_ent->ip_ver)
			{
				printf("\tsip: "IPV6_OCTET_FMT"\n", IPV6_OCTET_EXPAND(ioc_ent->sip));
				printf("\tdip: "IPV6_OCTET_FMT"\n", IPV6_OCTET_EXPAND(ioc_ent->dip));
			}
			printf("---------------------------------\n");

			tbl_used_len += sizeof(udb_vp_ioc_entry_t);
		}
		free(buf);
		free_rule_db(&rule_head);
	}
	return ret;

}

int get_vp(char *cmd)
{
	int flag;
	if (!strcmp(cmd, "0"))
		flag = 0;
	else if (!strcmp(cmd, "2"))
		flag = 2;
	else
		flag = 0;

	return _get_vp(flag);
}

int wrs_url_main()
{
	// TrendMicro define
	return get_wrs_url();
}

void redirect_page_status(int cat_id, long int *retval, struct request_rec *r)
{
	int ret = 0;
	unsigned int e, buf_pos, ioc_buf;
	char *buf;
	int checked = 0;
	char out[256]; // output buffer

	memset(out, 0, sizeof(out));

	udb_url_ioctl_list_t *tbl = NULL;

	ret = get_fw_wrs_url_list((void **)&buf, &ioc_buf);
	if (ret)
	{
		printf("Error: get user!(%d)\n", ret);
	}

	if (buf)
	{
		tbl = (udb_url_ioctl_list_t *)buf;
		buf_pos = sizeof(udb_url_ioctl_list_t);

		for (e=0; e < tbl->entry_cnt; e++)
		{
			char buff[18]; // MAC

			// action : block, if not, continue
			if ((tbl->entry[e].action == 0)) continue;
			// check the lastest matched id
			if (tbl->entry[e].cat_id != cat_id) continue;

			snprintf(buff, sizeof(buff), MAC_OCTET_FMT, MAC_OCTET_EXPAND(tbl->entry[e].mac));
			snprintf(out, sizeof(out), "[\"%s\", \"%s\", \"%d\"]", buff, tbl->entry[e].domain, cat_id);
			BWDPI_DBG("buf=%s\n", buf);
			*retval += so_printf(r, out);
			checked = 1;

			if (tbl->entry[e].cat_id == cat_id) break;
		}
		free(buf);
	}

	// if not found any matched category id, return ["", "", ""]
	if (checked == 0)
	{
		snprintf(out, sizeof(out), "[\"\", \"\", \"\"]");
		BWDPI_DBG("out=%s\n", out);
		*retval += so_printf(r, out);
	}
}

int get_app_patrol_main()
{
	// TrendMicro define
	return get_app_patrol();
}

int static _get_anomaly(int flag)
{
	int ret = 0;
	unsigned int e, buf_pos, ioc_buf;
	char *buf;

	udb_ano_ioc_entry_list_t *tbl = NULL;

	//process ioctl request & response
	ret = get_fw_anomaly_list((void **)&buf, &ioc_buf, flag);
	if (ret)
	{
		printf("Error: get %s(%d)\n", __func__, ret);
	}

	if (buf)
	{
		tbl = (udb_ano_ioc_entry_list_t *) buf;
		buf_pos = sizeof(udb_ano_ioc_entry_list_t);

		LIST_HEAD(rule_head);
		init_rule_db(&rule_head);

		printf("---entry_cnt = %u ---\n", tbl->cnt);
		printf("%-10s\t%-18s\t%-8s\t%-1s\t%-1s\t%s\n", "time", "mac", "rule_id", "hit_cnt", "action", "rule_name");
		printf("-----------------------------------------------------------\n");
		for (e=0; e < tbl->cnt; e++)
		{
			printf("%-10llu\t", tbl->entry[e].time);
			printf(MAC_OCTET_FMT"\t", MAC_OCTET_EXPAND(tbl->entry[e].mac));
			printf("%-6u\t", tbl->entry[e].rule_id);
			printf("%-6u\t", tbl->entry[e].hit_cnt);
			printf("%-3s\t", tbl->entry[e].action == 1 ? "1-Block" : tbl->entry[e].action == 2 ? "2-Monitor" : "0-Accept");
			printf("%s\n", search_rule_db(&rule_head, (unsigned)tbl->entry[e].rule_id));
			printf("\n");
		}
		free(buf);
		free_rule_db(&rule_head);
	}
	return ret;
}

int get_anomaly_main(char *cmd)
{
	int flag;
	if (!strcmp(cmd, "0"))
		flag = 0;
	else if (!strcmp(cmd, "2"))
		flag = 2;
	else
		flag = 0;

	return _get_anomaly(flag);
}
