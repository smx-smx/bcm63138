/*
 * Copyright 2014 Trend Micro Incorporated
 * Redistribution and use in source and binary forms, with or without modification, 
 * are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice, 
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, 
 *    this list of conditions and the following disclaimer in the documentation 
 *    and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its contributors 
 *    may be used to endorse or promote products derived from this software without 
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND 
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED 
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. 
 * IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, 
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT 
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR 
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, 
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY 
 * OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>

#include "udb/shell/shell_ioctl.h"

#include "ioc_common.h"
#include "ioc_vp.h"

int get_fw_vp_list(void **output, unsigned int *buf_used_len)
{
	const int buf_len = (sizeof(udb_vp_ioc_entry_t) * UDB_VIRTUAL_PATCH_LOG_SIZE);
	udb_shell_ioctl_t msg;

	*output = calloc(buf_len, sizeof(char));
	if (!*output)
	{
		DBG("Cannot allocate buffer space %u bytes", buf_len);
		return -1;
	}

	/* prepare and do ioctl */
	udb_shell_init_ioctl_entry(&msg);
	msg.nr = UDB_IOCTL_NR_VP;
	msg.op = UDB_IOCTL_VP_OP_GET_LOG;

	udb_shell_ioctl_set_out_buf(&msg, (*output), buf_len, buf_used_len);

	return run_ioctl(UDB_SHELL_IOCTL_CHRDEV_PATH, UDB_SHELL_IOCTL_CMD_VP, &msg);
}

int set_fw_vp(void *input, unsigned int length)
{
	udb_shell_ioctl_t msg;

	/* prepare and do ioctl */
	udb_shell_init_ioctl_entry(&msg);
	msg.nr = UDB_IOCTL_NR_VP;
	msg.op = UDB_IOCTL_VP_OP_SET;
	udb_shell_ioctl_set_in_raw(&msg, input, length);

	if (0 > run_ioctl(UDB_SHELL_IOCTL_CHRDEV_PATH, UDB_SHELL_IOCTL_CMD_VP, &msg))
	{
		return -1;
	}

	return 0;
}

static int get_vp(void)
{
	int ret = 0;
	unsigned int ioc_buf;
	char *buf;

	LIST_HEAD(rule_head);
	init_rule_db(&rule_head);

	ret = get_fw_vp_list((void **) &buf, &ioc_buf);

	if (ret)
	{
		DBG("Error: get user!(%d)\n", ret);
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
			if (ioc_ent->role == IPS_ROLE_ATT)
			{
				printf("\trole: attacker\n");
			}
			else if (ioc_ent->role == IPS_ROLE_VIC)
			{
				printf("\trole: victim\n");
			}
			else
			{
				printf("\trole: unknown\n");
			}
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
	}

	free_rule_db(&rule_head);

	return ret;

}

int vp_options_init(struct cmd_option *cmd)
{
#define HELP_LEN_MAX 1024
	int i = 0, j;
	static char help[HELP_LEN_MAX];
	int len = 0;

	cmd->opts[i].action = ACT_VP_GET_LOG;
	cmd->opts[i].name = "get_vp";
	cmd->opts[i].cb = get_vp;
	i++;

	len += snprintf(help + len, HELP_LEN_MAX - len, "%*s \n",
		HELP_INDENT_L, "");

	for (j = 0; j < i; j++)
	{
		len += snprintf(help + len, HELP_LEN_MAX - len, "%*s %s\n",
			HELP_INDENT_L, (j == 0) ? "vp actions:" : "",
			cmd->opts[j].name);
	}

	cmd->help = help;

	return 0;
}

