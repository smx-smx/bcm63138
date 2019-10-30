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

#include <linux/version.h>
#include <linux/types.h>
#include <linux/skbuff.h>
#include <net/netlink.h>
#include <net/sock.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
#include <net/netfilter/nf_conntrack.h>
#else
#include <linux/netfilter_ipv4/ip_conntrack.h>
#endif

#include "tdts_udb.h"

#include "forward_config.h"

#include "fw_action.h"

#include "fw_internal.h"

#define PROC_FORD_WRS  "bw_ford_wrs"

static struct sock *wrs_nl_sock = NULL;

atomic_t wrs_url_query_cnt = ATOMIC_INIT(0);
atomic_t wrs_url_query_cc_cnt = ATOMIC_INIT(0);
atomic_t wrs_resp_recvd	= ATOMIC_INIT(0);
atomic_t wrs_cc_resp_recvd = ATOMIC_INIT(0);
atomic_t wrs_resp_miss_count = ATOMIC_INIT(0);
atomic_t wrs_resp_cc_miss_count = ATOMIC_INIT(0);

static void
wrs_msg_handler(struct sk_buff *skb)
{
	if (skb->len >= sizeof(struct nlmsghdr) && skb->data)
	{
		struct nlmsghdr *nlh = (struct nlmsghdr *)skb->data;
		uint8_t *msg = (uint8_t *)NLMSG_DATA(nlh);
		int len = nlh->nlmsg_len - sizeof(struct nlmsghdr);

		udb_shell_usr_msg_handler(
			msg, len, nlh->nlmsg_pid, nlh->nlmsg_type);
	}
}

static int send_wrs_query_to_user(usr_msg_hdr_t *msg_hdr, uint8_t *msg)
{
	struct sk_buff *nskb = NULL;
	struct nlmsghdr *nlh = NULL;
	uint8_t *data = NULL;
	int ret = 0;

	nskb = 	nlmsg_new(msg_hdr->msg_len, GFP_ATOMIC);
	if (unlikely(!nskb))
	{
		ERR("Failed to alloc. SKB.\n");
		return BW_ERR;
	}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,0))
	nlh = nlmsg_put(nskb, 0, 0, msg_hdr->msg_type, msg_hdr->msg_len, 0);
#else
	nlh = NLMSG_PUT(nskb, 0, 0, msg_hdr->msg_type, msg_hdr->msg_len);
#endif

	if (unlikely(!nlh))
	{
		DBG("nlmsg_failure\n");
		goto nlmsg_failure;
	}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,0))
	data = (void *)nlmsg_data(nlh);
#else
	data = (void *)NLMSG_DATA(nlh);
#endif

	memcpy(data, msg, msg_hdr->msg_len);

	ret = netlink_unicast(wrs_nl_sock, nskb, msg_hdr->usr_pid, MSG_DONTWAIT);
	if (ret < 0)
	{
		// Kernel will handle skb, DO NOT free skb here.
		return BW_ERR;
	}

	return BW_OK;

nlmsg_failure:
	if (nskb)
	{
		kfree_skb(nskb);
	}

	return BW_ERR;
}

#if 0
static tdts_pkt_parameter_t *async_prepare(tdts_pkt_parameter_t *param)
{
	return param;
}
#endif

static int do_async_send(void *param, tdts_res_t fw_res)
{
	struct sk_buff *skb = NULL;
	int verdict = NF_ACCEPT, ret = NF_ACCEPT;
	unsigned char ip_ver = 0;
	tdts_udb_param_t *fw_param = param;

	/* Copy HOOK_PROLOG but free param and pkt */
	if (unlikely(rmmod_in_progress))
	{
		if (likely(fw_param && fw_param->skb_ptr))
		{
			kfree_skb(fw_param->skb_ptr);
		}

		return ret;
	}
	__get_cpu_var(handle_pkt) = true;

	if (unlikely(!fw_param || !fw_param->skb_ptr || !fw_param->skb_dev))
	{
		HOOK_EPILOG(ret);
	}

	skb = fw_param->skb_ptr;

	DBG("do_async_send: pvt = %p, skb = %p\n", fw_param->skb_ptr, skb);
	if (TDTS_RES_ACCEPT == fw_res)
	{
		verdict = NF_ACCEPT;

		switch (fw_param->hook)
		{
		case TDTS_HOOK_NF_FORD:
			if (!fw_param->dev.fw_send)
			{
				goto __drop;
			}

			ip_ver = ((ETH_P_IP == ntohs(skb->protocol)) ? 4 : 6);
			MY_NF_HOOK_THRESH(
				(4 == ip_ver) ? PF_INET : PF_INET6,
				NF_INET_FORWARD,
				fw_param->dev.fw_sk,
				skb,
				fw_param->dev.fw_indev,
				fw_param->dev.fw_outdev,
				fw_param->dev.fw_send,
				(4 == ip_ver) ? (NF_IP_PRI_FILTER + 1) : (NF_IP6_PRI_FILTER + 1));
			break;

		default:
			goto __drop;
			break;
		}
	}
	else
	{
__drop:
		verdict = NF_DROP;

		kfree_skb(skb);
	}

	/* Return WRS action, not app patrol action */
	HOOK_EPILOG(verdict);
}

void wrs_set_fw_param_cb(tdts_udb_param_t *fw_param)
{
	if (fw_param)
	{
		fw_param->send_wrs_query_to_user = send_wrs_query_to_user;
		fw_param->async_send = do_async_send;
	}
}

#if 0
static int ford_read_wrs_cnt(
	char *buf, char **start, off_t offset, int count, int *eof, void *data)
{
	unsigned int len = 0;

	len += sprintf(buf + len, "Total URL Query sent: %d\n", atomic_read(&wrs_url_query_cnt));
	len += sprintf(buf + len, "Total URL CC Query sent: %d\n", atomic_read(&wrs_url_query_cc_cnt));
	len += sprintf(buf + len, "Total URL Resp. recvd.: %d\n", atomic_read(&wrs_resp_recvd));
	len += sprintf(buf + len, "Total URL CC Resp. recvd.: %d\n", atomic_read(&wrs_cc_resp_recvd));
	len += sprintf(buf + len, "Total URL Query Resp. missed: %d\n", atomic_read(&wrs_resp_miss_count));
	len += sprintf(buf + len, "Total URL CC Query Resp. missed: %d\n", atomic_read(&wrs_resp_cc_miss_count));

	*eof = 1;
	return len;
}
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27))
static void wrs_msg_handle_sk(struct sock *sk, int len)
{
	struct sk_buff *skb = skb_dequeue(&sk->sk_receive_queue);

	while (skb && skb->len)
	{
		wrs_msg_handler(skb);
		kfree_skb(skb);
		skb = skb_dequeue(&sk->sk_receive_queue);
	}
}
#endif

int wrs_init(void)
{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,8,0))
	struct netlink_kernel_cfg cfg = {
		.input = wrs_msg_handler,
	};

	wrs_nl_sock = netlink_kernel_create(&init_net, TMCFG_APP_K_TDTS_UDBFW_WRS_NETLINK_ID, &cfg);
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27))
	wrs_nl_sock = netlink_kernel_create(&init_net
		, TMCFG_APP_K_TDTS_UDBFW_WRS_NETLINK_ID, 0, wrs_msg_handler, NULL, THIS_MODULE);
#else
	wrs_nl_sock = netlink_kernel_create(TMCFG_APP_K_TDTS_UDBFW_WRS_NETLINK_ID, 
			0, wrs_msg_handle_sk, NULL, THIS_MODULE);
#endif

	if (!wrs_nl_sock)
	{
		DBG("netlink_kernel_create() failed\n");
		return -1;
	}

	return 0;
}

void wrs_deinit(void)
{
	if (wrs_nl_sock)
	{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)
		netlink_kernel_release(wrs_nl_sock);
#else
		sock_release(wrs_nl_sock->sk_socket);
#endif
		DBG("Release URL query netlink\n");
	}
}


