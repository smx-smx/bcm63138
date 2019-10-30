
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include "arcgpl.h"
#include "asus_nvram.h"

typedef struct _PARA_MAP
{
	char *nvram_name;
	char *arc_name;
} PARA_MAP;

PARA_MAP maps[] =
{
	{"acc_num" ,"ARC_USB_ACCOUNT_TotalUserCount"},
	{"http_username" ,"ARC_USB_ACCOUNT_0_Name"},
	{"http_passwd" ,"ARC_USB_ACCOUNT_0_Password"},
	{"productid", "ARC_SYS_ModelName"},	
	{"odmpid", "ARC_SYS_ModelName"},	
	{"lan_ipaddr", "ARC_LAN_0_IP4_Addr"},	
	{"ddns_enable_x", "ARC_DDNS_0_Enable"},
	{"ddns_hostname_x", "ARC_DDNS_0_HostName"},
	{"local_domain", "ARC_LAN_0_DomainName"},
	{"preferred_lang", "ARC_UI_Language"},
	{"dms_enable", "ARC_USB_DLNA_Enable"},
	{"firmver", "ARC_SYS_FWVersion"},
	{"buildno", "ARC_SYS_FWSubVersion"},
	{"lan_hwaddr", "ARC_LAN_0_MACaddr"},
	{"apps_sq", "ARC_PROJ_ASUS_AUTO_FW_SQ_Enable"},
	/* Web History */
	{"wh_bkp_enable", "ASUS_wh_bkp_enable"},
	{"wh_bkp_path", "ASUS_wh_bkp_path"},
	{"wh_bkp_period", "ASUS_wh_bkp_period"},
	{"wh_clear", "ASUS_wh_clear"},
	{"wh_enable", "ASUS_wh_enable"},
	{"wh_max", "ASUS_wh_max"},
	{"log_bkp_nonhide", "ASUS_log_bkp_nonhide"},
	/* TrendMicro */
	{"wrs_protect_enable", "ASUS_wrs_protect_enable"},
	{"wrs_mals_enable", "ASUS_wrs_mals_enable"},
	{"wrs_cc_enable", "ASUS_wrs_cc_enable"},
	{"wrs_vp_enable", "ASUS_wrs_vp_enable"},
	{"wrs_enable", "ASUS_wrs_enable"},
	{"wrs_rulelist", "ASUS_wrs_rulelist"},
	{"wrs_app_enable", "ASUS_wrs_app_enable"},
	{"wrs_app_rulelist", "ASUS_wrs_app_rulelist"},
	{"wrs_mail_bit", "ASUS_wrs_mail_bit"},
	{"wrs_mals_t", "ASUS_wrs_mals_t"},
	{"wrs_cc_t", "ASUS_wrs_cc_t"},
	{"wrs_vp_t", "ASUS_wrs_vp_t"},
	{"bwdpi_db_enable", "ASUS_bwdpi_db_enable"},
	{"bwdpi_rsa_check", "ASUS_bwdpi_rsa_check"},
	{"bwdpi_alive", "ASUS_bwdpi_alive"},
	{"bwdpi_app_rulelist", "ASUS_bwdpi_app_rulelist"},
	{"bwdpi_sig_ver", "ASUS_bwdpi_sig_ver"},
	{"TM_EULA", "ASUS_TM_EULA"},
	{"apps_analysis", "ASUS_apps_analysis"},
	{"bwdpi_wh_enable", "ASUS_bwdpi_wh_enable"},
	{"bwdpi_wh_stamp", "ASUS_bwdpi_wh_stamp"},
	{"sig_update_t", "ASUS_sig_update_t"},
	/* PPPoE host-unique & WiFi scheduling */
	{"wan_pppoe_hostuniq", "ASUS_wan_pppoe_hostuniq"},
	{"wl0_sched", "ASUS_wl0_sched"},
	{"wl1_sched", "ASUS_wl1_sched"},
	{"wl0_timesched", "ASUS_wl0_timesched"},
	{"wl1_timesched", "ASUS_wl1_timesched"},
	{"wl0_radio", "ARC_WLAN_24G_Enable"},
	{"wl1_radio", "ARC_WLAN_5G_Enable"},
};

#define map_size sizeof(maps)/sizeof(PARA_MAP)

const char *nvram_name[] = 
{
        "acs_ifnames",
        "boardnum",
        "lan_ifname",
        "lan_ifnames",
        "lan_wps_oob",
        "wl0.1_akm",
        "wl0.1_bss_enabled",
        "wl0.1_bss_maxassoc",
        "wl0.1_closed",
        "wl0.1_crypto",
        "wl0.1_hwaddr",
        "wl0.1_ifname",
        "wl0.1_macmode",
        "wl0.1_mode",
        "wl0.1_radio",
        "wl0.1_ssid",
        "wl0.1_wep",
        "wl0.1_wme",
        "wl0.1_wpa_psk",
        "wl0.1_wps_mode",
        "wl0.2_akm",
        "wl0.2_bss_enabled",
        "wl0.2_bss_maxassoc",
        "wl0.2_closed",
        "wl0.2_crypto",
        "wl0.2_hwaddr",
        "wl0.2_ifname",
        "wl0.2_macmode",
        "wl0.2_mode",
        "wl0.2_radio",
        "wl0.2_ssid",
        "wl0.2_wep",
        "wl0.2_wme",
        "wl0.2_wpa_psk",
        "wl0.2_wps_mode",
        "wl0.3_akm",
        "wl0.3_bss_enabled",
        "wl0.3_bss_maxassoc",
        "wl0.3_closed",
        "wl0.3_crypto",
        "wl0_3gpplist",
        "wl0.3_hwaddr",
        "wl0.3_ifname",
        "wl0.3_macmode",
        "wl0.3_mode",
        "wl0.3_radio",
        "wl0.3_ssid",
        "wl0.3_wep",
        "wl0.3_wme",
        "wl0.3_wpa_psk",
        "wl0.3_wps_mode",
        "wl0_acs_chan_dwell_time",
        "wl0_acs_chan_flop_period",
        "wl0_acs_ci_scan_timeout",
        "wl0_acs_ci_scan_timer",
        "wl0_acs_cs_scan_timer",
        "wl0_acs_dfs",
        "wl0_acs_dfsr_activity",
        "wl0_acs_dfsr_deferred",
        "wl0_acs_dfsr_immediate",
        "wl0_acs_excl_chans",
        "wl0_acs_fcs_mode",
        "wl0_acs_scan_entry_expire",
        "wl0_acs_tx_idle_cnt",
		"wl0_acs_use_escan",
        "wl0_akm",
        "wl0_ampdu",
        "wl0_ampdu_rr_rtylimit_tid",
        "wl0_ampdu_rtylimit_tid",
        "wl0_amsdu",
        "wl0_anonai",
        "wl0_antdiv",
        "wl0_ap_isolate",
        "wl0_assoc_retry_max",
        "wl0_auth",
        "wl0_auth_mode",
        "wl0_bcn",
        "wl0_bcn_rotate",
        "wl0_bss_enabled",
        "wl0_bss_maxassoc",
        "wl0_bss_opmode_cap_reqd",
        "wl0_bw_cap",
        "wl0_chanspec",
        "wl0_closed",
        "wl0_concaplist",
        "wl0_corerev",
        "wl0_country_code",
        "wl0_country_rev",
        "wl0_crypto",
        "wl0_dcs_csa_unicast",
        "wl0_dfs_pref",
        "wl0_domainlist",
        "wl0_dtim",
        "wl0_frag",
        "wl0_frameburst",
        "wl0_gascbdel",
        "wl0_gmode",
        "wl0_gmode_protection",
        "wl0_hessid",
        "wl0_homeqlist",
        "wl0_hs2cap",
        "wl0_hsflag",
        "wl0_hwaddr",
        "wl0_hw_rxchain",
        "wl0_hw_txchain",
        "wl0_ifname",
        "wl0_infra",
        "wl0_intfer_cnt",
        "wl0_intfer_period",
        "wl0_intfer_tcptxfail",
        "wl0_intfer_txfail",
        "wl0_ipv4addr",
        "wl0_ipv6addr",
        "wl0_iwnettype",
        "wl0_key",
        "wl0_key1",
        "wl0_key2",
        "wl0_key3",
        "wl0_key4",
        "wl0_lazywds",
        "wl0_leddc",
        "wl0_maclist",
        "wl0_macmode",
        "wl0_maxassoc",
        "wl0_mcast_regen_bss_enable",
        "wl0_mfp",
        "wl0_mode",
        "wl0_mrate",
        "wl0_nar",
        "wl0_nar_transit_limit",
        "wl0_nband",
        "wl0_netauthlist",
        "wl0_net_reauth",
        "wl0_nmcsidx",
        "wl0_nmode",
        "wl0_obss_coex",
        "wl0_opercls",
        "wl0_oplist",
        "wl0_osu_frndname",
        "wl0_osu_icons",
        "wl0_osu_method",
        "wl0_osu_nai",
        "wl0_osu_servdesc",
        "wl0_osu_ssid",
        "wl0_osu_uri",
        "wl0_ouilist",
        "wl0_phytype",
        "wl0_phytypes",
        "wl0_plcphdr",
        "wl0_probresp_mf",
        "wl0_probresp_sw",
        "wl0_pspretend_retry_limit",
        "wl0_psr_mrpt",
        "wl0_qosmapie",
        "wl0_radio",
        "wl0_radioids",
        "wl0_radio_pwrsave_enable",
        "wl0_radio_pwrsave_level",
        "wl0_radio_pwrsave_pps",
        "wl0_radio_pwrsave_quiet_time",
        "wl0_radio_pwrsave_stas_assoc_check",
        "wl0_radius_ipaddr",
        "wl0_radius_key",
        "wl0_radius_port",
        "wl0_rate",
        "wl0_rateset",
        "wl0_realmlist",
        "wl0_reg_mode",
        "wl0_rifs_advert",
        "wl0_rts",
        "wl0_rxchain",
        "wl0_rxchain_pwrsave_enable",
        "wl0_rxchain_pwrsave_pps",
        "wl0_rxchain_pwrsave_quiet_time",
        "wl0_rxchain_pwrsave_stas_assoc_check",
        "wl0_rxstreams",
        "wl0_ssd_type",
        "wl0_ssid",
        "wl0_sta_retry_time",
        "wl0_stbc_rx",
        "wl0_stbc_tx",
        "wl0_taf_enable",
        "wl0_txbf_bfe_cap",
        "wl0_txbf_bfr_cap",
        "wl0_txbf_imp",
        "wl0_txchain",
        "wl0_txstreams",
        "wl0_unit",
        "wl0_venuegrp",
        "wl0_venuelist",
        "wl0_venuetype",
        "wl0_vht_features",
        "wl0_vifs",
        "wl0_vlan_prio_mode",
        "wl0_wanmetrics",
        "wl0_wds",
        "wl0_wds_timeout",
        "wl0_wep",
        "wl0_wet_tunnel",
        "wl0_wme",
        "wl0_wme_ap_be",
        "wl0_wme_ap_bk",
        "wl0_wme_apsd",
        "wl0_wme_ap_vi",
        "wl0_wme_ap_vo",
        "wl0_wme_bss_disable",
        "wl0_wme_no_ack",
        "wl0_wme_sta_be",
        "wl0_wme_sta_bk",
        "wl0_wme_sta_vi",
        "wl0_wme_sta_vo",
        "wl0_wme_txp_be",
        "wl0_wme_txp_bk",
        "wl0_wme_txp_vi",
        "wl0_wme_txp_vo",
        "wl0_wmf_bss_enable",
        "wl0_wmf_mdata_sendup",
        "wl0_wmf_ucast_upnp",
        "wl0_wmf_ucigmp_query",
        "wl0_wpa_gtk_rekey",
        "wl0_wpa_psk",
        "wl0_wps_config_state",
        "wl0_wps_mode",
        "wl0_wps_reg",
		"wl1.1_akm",
        "wl1.1_bss_enabled",
        "wl1.1_bss_maxassoc",
        "wl1.1_closed",
        "wl1.1_crypto",
        "wl1.1_hwaddr",
        "wl1.1_ifname",
        "wl1.1_macmode",
        "wl1.1_mode",
        "wl1.1_radio",
        "wl1.1_ssid",
        "wl1.1_wep",
        "wl1.1_wme",
        "wl1.1_wpa_psk",
        "wl1.1_wps_mode",
        "wl1.2_akm",
        "wl1.2_bss_enabled",
        "wl1.2_bss_maxassoc",
        "wl1.2_closed",
        "wl1.2_crypto",
        "wl1.2_hwaddr",
        "wl1.2_ifname",
        "wl1.2_macmode",
        "wl1.2_mode",
        "wl1.2_radio",
        "wl1.2_ssid",
        "wl1.2_wep",
        "wl1.2_wme",
        "wl1.2_wpa_psk",
        "wl1.2_wps_mode",
        "wl1.3_akm",
        "wl1.3_bss_enabled",
        "wl1.3_bss_maxassoc",
        "wl1.3_closed",
        "wl1.3_crypto",
        "wl1_3gpplist",
        "wl1.3_hwaddr",
        "wl1.3_ifname",
        "wl1.3_macmode",
        "wl1.3_mode",
        "wl1.3_radio",
        "wl1.3_ssid",
        "wl1.3_wep",
        "wl1.3_wme",
        "wl1.3_wpa_psk",
        "wl1.3_wps_mode",
        "wl1_acs_chan_dwell_time",
        "wl1_acs_chan_flop_period",
        "wl1_acs_ci_scan_timeout",
        "wl1_acs_ci_scan_timer",
        "wl1_acs_cs_scan_timer",
        "wl1_acs_dfs",
        "wl1_acs_dfsr_activity",
        "wl1_acs_dfsr_deferred",
        "wl1_acs_dfsr_immediate",
        "wl1_acs_excl_chans",
        "wl1_acs_fcs_mode",
        "wl1_acs_scan_entry_expire",
        "wl1_acs_tx_idle_cnt",
		"wl1_acs_use_escan",
        "wl1_akm",
        "wl1_ampdu",
        "wl1_ampdu_rr_rtylimit_tid",
        "wl1_ampdu_rtylimit_tid",
        "wl1_amsdu",
        "wl1_anonai",
        "wl1_antdiv",
        "wl1_ap_isolate",
        "wl1_assoc_retry_max",
        "wl1_auth",
        "wl1_auth_mode",
        "wl1_bcn",
        "wl1_bcn_rotate",
        "wl1_bss_enabled",
        "wl1_bss_maxassoc",
        "wl1_bss_opmode_cap_reqd",
        "wl1_bw_cap",
        "wl1_chanspec",
        "wl1_closed",
        "wl1_concaplist",
        "wl1_corerev",
        "wl1_country_code",
        "wl1_country_rev",
        "wl1_crypto",
        "wl1_dcs_csa_unicast",
        "wl1_dfs_pref",
        "wl1_domainlist",
        "wl1_dtim",
        "wl1_frag",
        "wl1_frameburst",
        "wl1_gascbdel",
        "wl1_gmode",
        "wl1_gmode_protection",
        "wl1_hessid",
        "wl1_homeqlist",
        "wl1_hs2cap",
        "wl1_hsflag",
        "wl1_hwaddr",
        "wl1_hw_rxchain",
        "wl1_hw_txchain",
        "wl1_ifname",
        "wl1_infra",
        "wl1_intfer_cnt",
        "wl1_intfer_period",
        "wl1_intfer_tcptxfail",
        "wl1_intfer_txfail",
        "wl1_ipv4addr",
        "wl1_ipv6addr",
        "wl1_iwnettype",
        "wl1_key",
        "wl1_key1",
        "wl1_key2",
        "wl1_key3",
        "wl1_key4",
        "wl1_lazywds",
        "wl1_leddc",
        "wl1_maclist",
        "wl1_macmode",
        "wl1_maxassoc",
        "wl1_mcast_regen_bss_enable",
        "wl1_mfp",
        "wl1_mode",
        "wl1_mrate",
        "wl1_nar",
        "wl1_nar_transit_limit",
        "wl1_nband",
        "wl1_netauthlist",
        "wl1_net_reauth",
        "wl1_nmcsidx",
        "wl1_nmode",
        "wl1_obss_coex",
        "wl1_opercls",
        "wl1_oplist",
        "wl1_osu_frndname",
        "wl1_osu_icons",
        "wl1_osu_method",
        "wl1_osu_nai",
        "wl1_osu_servdesc",
        "wl1_osu_ssid",
        "wl1_osu_uri",
        "wl1_ouilist",
        "wl1_phytype",
        "wl1_phytypes",
        "wl1_plcphdr",
        "wl1_probresp_mf",
        "wl1_probresp_sw",
        "wl1_pspretend_retry_limit",
        "wl1_psr_mrpt",
        "wl1_qosmapie",
        "wl1_radio",
        "wl1_radioids",
        "wl1_radio_pwrsave_enable",
        "wl1_radio_pwrsave_level",
        "wl1_radio_pwrsave_pps",
        "wl1_radio_pwrsave_quiet_time",
        "wl1_radio_pwrsave_stas_assoc_check",
        "wl1_radius_ipaddr",
        "wl1_radius_key",
        "wl1_radius_port",
        "wl1_rate",
        "wl1_rateset",
        "wl1_realmlist",
        "wl1_reg_mode",
        "wl1_rifs_advert",
        "wl1_rts",
        "wl1_rxchain",
        "wl1_rxchain_pwrsave_enable",
        "wl1_rxchain_pwrsave_pps",
        "wl1_rxchain_pwrsave_quiet_time",
        "wl1_rxchain_pwrsave_stas_assoc_check",
        "wl1_rxstreams",
        "wl1_ssd_type",
        "wl1_ssid",
        "wl1_sta_retry_time",
        "wl1_stbc_rx",
        "wl1_stbc_tx",
        "wl1_taf_enable",
        "wl1_txbf_bfe_cap",
        "wl1_txbf_bfr_cap",
        "wl1_txbf_imp",
        "wl1_txchain",
        "wl1_txstreams",
        "wl1_unit",
        "wl1_venuegrp",
        "wl1_venuelist",
        "wl1_venuetype",
        "wl1_vht_features",
        "wl1_vifs",
        "wl1_vlan_prio_mode",
        "wl1_wanmetrics",
        "wl1_wds",
        "wl1_wds_timeout",
        "wl1_wep",
        "wl1_wet_tunnel",
        "wl1_wme",
        "wl1_wme_ap_be",
        "wl1_wme_ap_bk",
        "wl1_wme_apsd",
        "wl1_wme_ap_vi",
        "wl1_wme_ap_vo",
        "wl1_wme_bss_disable",
        "wl1_wme_no_ack",
        "wl1_wme_sta_be",
        "wl1_wme_sta_bk",
        "wl1_wme_sta_vi",
        "wl1_wme_sta_vo",
        "wl1_wme_txp_be",
        "wl1_wme_txp_bk",
        "wl1_wme_txp_vi",
        "wl1_wme_txp_vo",
        "wl1_wmf_bss_enable",
        "wl1_wmf_mdata_sendup",
        "wl1_wmf_ucast_upnp",
        "wl1_wmf_ucigmp_query",
        "wl1_wpa_gtk_rekey",
        "wl1_wpa_psk",
        "wl1_wps_config_state",
        "wl1_wps_mode",
        "wl1_wps_reg",
        "wps_aplockdown",
        "wps_config_method",
        "wps_device_name",
        "wps_device_pin",
        "wps_mfstring",
        "wps_modelname",
        "wps_modelnum",
        "wps_proc_status",
        "wps_version2",
        "wps_wer_mode",
        "wps_msglevel",
};

#define nvram_size sizeof(nvram_name)/sizeof(char *)

static int MatchGetArg(char *arg, char *newArg, int argsize)
{
	int i;
	for (i = 0; i<map_size; i++)
	{
		if (strcmp(arg, maps[i].nvram_name) == 0)
		{
			strncpy(newArg, maps[i].arc_name, argsize-1);
			newArg[argsize -1] = '\0';
			return 1;
		}
	}

	if (strcmp(arg, "wan0_ipaddr") == 0)
	{
		char wan_proto[32];

		arcgpl_cfg_get("ARC_WAN_0_IP4_Proto", wan_proto, sizeof(wan_proto));
		if (strcmp(wan_proto, "pppoe") == 0 || strcmp(wan_proto, "pptp") == 0
			|| strcmp(wan_proto, "l2tp") == 0)
			strcpy(newArg, "ARC_WAN_0_PPP_GET_IP4_Addr");
		else
			strcpy(newArg, "ARC_WAN_0_IP4_Addr");
		return 1;
	}

	for (i = 0; i<nvram_size; i++)
	{
		if (strcmp(arg, nvram_name[i]) == 0)
			return 0;
	}

	snprintf(newArg, argsize, "ASUS_%s", arg);
	return 1;
}

static int MatchSetArg(char *arg, char *newArg, int argsize)
{
	char name[384];
	char *ptr;
	int len, i;

	ptr = strchr(arg, '=');
	if (ptr != NULL)
	{	
		len = ptr - arg;
		if (len >= sizeof(name))
			len = sizeof(name) -1;
		strncpy(name, arg, len);
		name[len] = '\0';
		for (i = 0; i<map_size; i++)
		{
			if (strcmp(name, maps[i].nvram_name) == 0)
			{
				snprintf(newArg, argsize, "%s%s", maps[i].arc_name, ptr);
				return 1;
			}
		}

		for (i = 0; i<nvram_size; i++)
		{
			if (strcmp(name, nvram_name[i]) == 0)
				return 0;
		}

		snprintf(newArg, argsize, "ASUS_%s", arg);
		return 1;
	}

	return 0;
}

static int char_to_ascii_safe(char *output, char *input, int outsize)
{
	char *src = (char *)input;
	char *dst = (char *)output;
	char *end = (char *)output + outsize - 1;
	char *escape = "[]"; // shouldn't be more?

	if (src == NULL || dst == NULL || outsize <= 0)
		return 0;

	for ( ; *src && dst < end; src++) {
		if ((*src >='0' && *src <='9') ||
		    (*src >='A' && *src <='Z') ||
		    (*src >='a' && *src <='z')) {
			*dst++ = *src;
		} else if (strchr(escape, *src)) {
			if (dst + 2 > end)
				break;
			*dst++ = '\\';
			*dst++ = *src;
		} else {
			if (dst + 3 > end)
				break;
			if( (unsigned char)*src >= 32 && (unsigned char)*src <= 127) {
				dst += sprintf(dst, "%%%.02X", (unsigned char)*src);
			}
		}
	}
	if (dst <= end)
		*dst = '\0';

	return dst - output;
}

static char *str_toupper(char *str)
{
	char *ptr;
	if (str)
	{
		ptr = str;
		while(*ptr != '\0')
		{
			*ptr = toupper((int)(*ptr));
			ptr++;
		}
	}
	return str;
}

static char *CatAccountList(char *buffer)
{
	int num, i;
	char name[128];
	char passwd[128];
	char trans[256];
	char para[128];
	char *ptr;
	char value[32];
	CFGList list;
	
	ptr = buffer;
	*ptr = '\0';
	memset(&list, 0, sizeof(CFGList));
	if (arcgpl_cfglist_get("ARC_USB_ACCOUNT", &list) > 0)
	{
		arcgpl_cfglist_search(&list, "ARC_USB_ACCOUNT_TotalUserCount", value, sizeof(value));
		num = atoi(value);
		for (i = 0; i<num; i++)
		{
			sprintf(para, "ARC_USB_ACCOUNT_%d_Name", i);
			arcgpl_cfglist_search(&list, para, name, sizeof(name));
			sprintf(para, "ARC_USB_ACCOUNT_%d_Password", i);
			arcgpl_cfglist_search(&list, para, passwd, sizeof(passwd));
			
			if (strlen(name) > 0 && strlen(passwd) > 0)
			{
				if (i > 0)
					ptr += sprintf(ptr, "<");
				ptr += sprintf(ptr, "%s>", name);
				if (char_to_ascii_safe(trans, passwd, sizeof(trans)) > 0)
					ptr += sprintf(ptr, "%s", trans);
			}
		}
		arcgpl_cfglist_free(&list);
	}
	return buffer;
}

static char *CatLongParameter(char *para, char *buffer, int bufsize)
{
	int num, i, len=0, sublen;
	char *ptr;
	CFGList list;
	CFGElm *elm;
	char ASUSname[64];
	char *part;

	ptr = buffer;
	*ptr = '\0';
	memset(&list, 0, sizeof(CFGList));

	snprintf(ASUSname, sizeof(ASUSname), "ASUS_%s", para);
	if (arcgpl_cfglist_get(ASUSname, &list) > 0)
	{
		elm = list.head;
		while(elm != NULL)
		{
			part = strrchr(elm->Name, '_');
			if ((part && strncmp(part, "_part", 5) == 0) && elm->Value)
			{
				sublen = strlen(elm->Value);
				if (len+sublen+1 < bufsize)
				{
					strcat(ptr+len, elm->Value);
					len += sublen;
				}
			}
			elm = elm->_next;
		}
		arcgpl_cfglist_free(&list);
	}
	
	return buffer;
}

static int SetLongParameter(const char *para, const char *var)
{
	char name[63];
	char value[449];
	char *ptr;
	int idx=0, crtlen, len = 0;
	
	crtlen = strlen(var);
	ptr = var;
	while(len < crtlen)
	{
		sprintf(name, "ASUS_%s_part%d", para, ++idx);
		if ((crtlen - len) > sizeof(value) -1)
		{
			strncpy(value, ptr, sizeof(value) -1);
			value[sizeof(value) -1] = '\0';
			arcgpl_cfg_set(name, value);
			len += (sizeof(value) -1);
			ptr = var+len;
		}
		else
		{
			arcgpl_cfg_set(name, ptr);
			break;
		}
	}

	sprintf(name, "ASUS_%s_part%d", para, ++idx);
	arcgpl_cfg_get(name, value, sizeof(value));
	while(strlen(value) > 0)
	{
		arcgpl_cfg_set(name, "");
		sprintf(name, "ASUS_%s_part%d", para, ++idx);
		arcgpl_cfg_get(name, value, sizeof(value));
	}

	return 0;
}

char *nvram_get(const char *name)
{
	static char buffer[16384];
	FILE *fp = NULL;
	pid_t pid;
	char *args[4];
	char newArg[512];
	char *end = NULL;
	
	buffer[0] = '\0'; 
	if (name == NULL)
		return buffer;

	if (strcmp(name, "acc_list") == 0)
	{
		return CatAccountList(buffer);
	}
	else if (strcmp(name, "https_crt_file") == 0 
		||strcmp(name, "share_link") == 0)
	{
		return CatLongParameter(name, buffer, sizeof(buffer));
	}

	args[0] = "/usr/sbin/nvram";
	args[1] = "get";
	args[2] = name;
	args[3] = NULL;
	
	if (MatchGetArg(name, newArg, sizeof(newArg)) == 1)
	{
		args[0] = "/usr/sbin/mng_cli";
		args[2] = newArg;
	}

	fp = exec_open(&pid, args);
	if (fp != NULL)
	{
		fgets(buffer, sizeof(buffer), fp);
		if ((end = strpbrk(buffer, "\r\n")) != NULL)
			*end = '\0';
		exec_close(pid, fp);
	}

	if (strcmp(name, "lan_hwaddr") == 0)
		str_toupper(buffer);

	return buffer;
}

char *nvram_safe_get(const char *name)
{
	return nvram_get(name);
}

int nvram_get_int(const char *name)
{
	return atoi(nvram_get(name));
}

int nvram_set_int(const char *key, int value)
{
	char nvramstr[16];

	snprintf(nvramstr, sizeof(nvramstr), "%d", value);
	return nvram_set(key, nvramstr);
}

int nvram_match(const char *name, const char *value)
{
	return strcmp(nvram_get(name), value) ? 0 : 1;
}

int nvarm_set_cmd(const char *arg)
{
	FILE *fp = NULL;
	pid_t pid;
	char *args[4];
	char newArg[512];

	args[0] = "/usr/sbin/nvram";
	args[1] = "set";
	args[2] = arg;
	args[3] = NULL;

	if (strncmp(arg, "https_crt_file=", 15) == 0)
	{
		return SetLongParameter("https_crt_file", arg+15);
	}
	else if (strncmp(arg, "share_link=", 11) == 0)
	{
		return SetLongParameter("share_link", arg+11);
	}

	if (MatchSetArg(arg, newArg, sizeof(newArg)) == 1)
	{
		args[0] = "/usr/sbin/mng_cli";
		args[2] = newArg;
	}

	fp = exec_open(&pid, args);
	if (fp != NULL)
	{
		exec_close(pid, fp);
	}

	return 0;
}

int nvram_set(const char *name, const char *value)
{
	char arg[512];

	if (name == NULL || value == NULL)
		return 0;
	snprintf(arg, sizeof(arg), "%s=%s", name, value);
	return nvarm_set_cmd(arg);
}

int nvram_commit()
{
	FILE *fp = NULL;
	pid_t pid;
	char *args[3];

	args[0] = "/usr/sbin/mng_cli";
	args[1] = "commit";
	args[2] = NULL;

	fp = exec_open(&pid, args);
	if (fp != NULL)
	{
		exec_close(pid, fp);
	}
	
	return 0;
}
	
