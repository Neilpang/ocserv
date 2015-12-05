/*
 * Copyright (C) 2015 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netdb.h>
#include <system.h>
#include <errno.h>
#include <limits.h>
#include <sys/ioctl.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <tlslib.h>
#include "common.h"
#include "str.h"
#include "setproctitle.h"
#include <sec-mod.h>
#include <ip-lease.h>
#include <route-add.h>
#include <ipc.pb-c.h>
#include <script-list.h>

#include <vpn.h>
#include <main.h>
#include <main-ban.h>
#include <ccan/list/list.h>

int handle_sec_mod_commands(main_server_st * s)
{
	struct iovec iov[3];
	uint8_t cmd;
	struct msghdr hdr;
	uint16_t length;
	uint8_t *raw;
	int ret, raw_len, e;
	void *pool = talloc_new(s);
	PROTOBUF_ALLOCATOR(pa, pool);
	BanIpMsg *tmsg = NULL;
	SecRefreshCookieKey *rmsg = NULL;

	if (pool == NULL)
		return -1;

	iov[0].iov_base = &cmd;
	iov[0].iov_len = 1;

	iov[1].iov_base = &length;
	iov[1].iov_len = 2;

	memset(&hdr, 0, sizeof(hdr));
	hdr.msg_iov = iov;
	hdr.msg_iovlen = 2;

	do {
		ret = recvmsg(s->sec_mod_fd, &hdr, 0);
	} while(ret == -1 && errno == EINTR);
	if (ret == -1) {
		e = errno;
		mslog(s, NULL, LOG_ERR,
		      "cannot obtain metadata from sec-mod socket: %s",
		      strerror(e));
		return ERR_BAD_COMMAND;
	}

	if (ret == 0) {
		mslog(s, NULL, LOG_ERR, "command socket for sec-mod closed");
		return ERR_BAD_COMMAND;
	}

	if (ret < 3 || cmd <= MIN_SM_MAIN_CMD || cmd >= MAX_SM_MAIN_CMD) {
		mslog(s, NULL, LOG_ERR, "main received invalid message from sec-mod of %u bytes (cmd: %u)\n",
		      (unsigned)length, (unsigned)cmd);
		return ERR_BAD_COMMAND;
	}

	mslog(s, NULL, LOG_DEBUG, "main received message '%s' from sec-mod of %u bytes\n",
	      cmd_request_to_str(cmd), (unsigned)length);

	raw = talloc_size(pool, length);
	if (raw == NULL) {
		mslog(s, NULL, LOG_ERR, "memory error");
		return ERR_MEM;
	}

	raw_len = force_read_timeout(s->sec_mod_fd, raw, length, MAIN_SEC_MOD_TIMEOUT);
	if (raw_len != length) {
		e = errno;
		mslog(s, NULL, LOG_ERR,
		      "cannot obtain data of cmd %u with length %u from sec-mod socket: %s",
		      (unsigned)cmd, (unsigned)length, strerror(e));
		ret = ERR_BAD_COMMAND;
		goto cleanup;
	}

	switch (cmd) {
	case SM_CMD_REFRESH_COOKIE_KEY:
		rmsg = sec_refresh_cookie_key__unpack(&pa, raw_len, raw);
		if (rmsg == NULL) {
			mslog(s, NULL, LOG_ERR, "error unpacking sec-mod data");
			ret = ERR_BAD_COMMAND;
			goto cleanup;
		}

		if (rmsg->key.len != sizeof(s->cookie_key)) {
			mslog(s, NULL, LOG_ERR, "received corrupt cookie key (%u bytes) from sec-mod", (unsigned)rmsg->key.len);
			ret = ERR_BAD_COMMAND;
			goto cleanup;
		}

		memcpy(s->prev_cookie_key, s->cookie_key, sizeof(s->cookie_key));
		s->prev_cookie_key_active = 1;

		memcpy(s->cookie_key, rmsg->key.data, sizeof(s->cookie_key));
		safe_memset(rmsg->key.data, 0, rmsg->key.len);

		mslog(s, NULL, LOG_INFO, "refreshed cookie key");
		break;

	case SM_CMD_AUTH_BAN_IP:{
			BanIpReplyMsg reply = BAN_IP_REPLY_MSG__INIT;

			tmsg = ban_ip_msg__unpack(&pa, raw_len, raw);
			if (tmsg == NULL) {
				mslog(s, NULL, LOG_ERR, "error unpacking sec-mod data");
				ret = ERR_BAD_COMMAND;
				goto cleanup;
			}
			ret = add_str_ip_to_ban_list(s, tmsg->ip, tmsg->score);
			if (ret < 0) {
				reply.reply =
				    AUTH__REP__FAILED;
			} else {
				/* no need to send a reply at all */
				ret = 0;
				goto cleanup;
			}

			reply.sid.data = tmsg->sid.data;
			reply.sid.len = tmsg->sid.len;
			reply.has_sid = tmsg->has_sid;

			mslog(s, NULL, LOG_DEBUG, "sending msg %s to sec-mod", cmd_request_to_str(SM_CMD_AUTH_BAN_IP_REPLY));

			ret = send_msg(NULL, s->sec_mod_fd, SM_CMD_AUTH_BAN_IP_REPLY,
				&reply, (pack_size_func)ban_ip_reply_msg__get_packed_size,
				(pack_func)ban_ip_reply_msg__pack);
			if (ret < 0) {
				mslog(s, NULL, LOG_ERR,
				      "could not send reply cmd %d.",
				      (unsigned)cmd);
				ret = ERR_BAD_COMMAND;
				goto cleanup;
			}
		}

		break;
	default:
		mslog(s, NULL, LOG_ERR, "unknown CMD from sec-mod 0x%x.", (unsigned)cmd);
		ret = ERR_BAD_COMMAND;
		goto cleanup;
	}

	ret = 0;
 cleanup:
	if (tmsg != NULL)
		ban_ip_msg__free_unpacked(tmsg, &pa);
	talloc_free(raw);
	talloc_free(pool);

	return ret;
}

static void append_routes(main_server_st *s, proc_st *proc, GroupCfgSt *gc)
{
	/* if we have known_iroutes, we must append them to the routes list */
	if (s->config->known_iroutes_size > 0 || s->config->append_routes) {
		char **old_routes = gc->routes;
		unsigned old_routes_size = gc->n_routes;
		unsigned i, j, append;
		unsigned to_append = 0;

		to_append = s->config->known_iroutes_size;
		if (s->config->append_routes)
			to_append += s->config->network.routes_size;

		gc->n_routes = 0;
		gc->routes = talloc_size(proc, sizeof(char*)*(old_routes_size+to_append));

		for (i=0;i<old_routes_size;i++) {
			gc->routes[i] = talloc_strdup(proc, old_routes[i]);
			if (gc->routes[i] == NULL)
				break;
			gc->n_routes++;
		}

		if (gc->routes) {
			/* Append any iroutes that are known and don't match the client's */
			for (i=0;i<s->config->known_iroutes_size;i++) {
				append = 1;
				for (j=0;j<gc->n_iroutes;j++) {
					if (strcmp(gc->iroutes[j], s->config->known_iroutes[i]) == 0) {
						append = 0;
						break;
					}
				}

				if (append) {
					gc->routes[gc->n_routes] = talloc_strdup(proc, s->config->known_iroutes[i]);
					if (gc->routes[gc->n_routes] == NULL)
						break;
					gc->n_routes++;
				}
			}
		}

		if (s->config->append_routes) {
			/* Append all global routes */
			for (i=0;i<s->config->network.routes_size;i++) {
				gc->routes[gc->n_routes] = talloc_strdup(proc, s->config->network.routes[i]);
				if (gc->routes[gc->n_routes] == NULL)
					break;
				gc->n_routes++;
			}

			/* Append no-routes */
			if (s->config->network.no_routes_size == 0)
				return;

			old_routes = gc->no_routes;
			old_routes_size = gc->n_no_routes;

			gc->n_no_routes = 0;
			gc->no_routes = talloc_size(proc, sizeof(char*)*(old_routes_size+s->config->network.no_routes_size));

			for (i=0;i<old_routes_size;i++) {
				gc->no_routes[i] = talloc_strdup(proc, old_routes[i]);
				if (gc->no_routes[i] == NULL)
					break;
				gc->n_no_routes++;
			}

			for (i=0;i<s->config->network.no_routes_size;i++) {
				gc->no_routes[gc->n_no_routes] = talloc_strdup(proc, s->config->network.no_routes[i]);
				if (gc->no_routes[gc->n_no_routes] == NULL)
					break;
				gc->n_no_routes++;
			}
		}
	}
}

static
void apply_default_config(main_server_st *s, proc_st *proc, GroupCfgSt *gc)
{
	if (!gc->has_no_udp) {
		gc->no_udp = (s->perm_config->udp_port!=0)?0:1;
		gc->has_no_udp = 1;
	}

	if (gc->routes == NULL) {
		gc->routes = s->config->network.routes;
		gc->n_routes = s->config->network.routes_size;
	}

	append_routes(s, proc, gc);

	if (gc->no_routes == NULL) {
		gc->no_routes = s->config->network.no_routes;
		gc->n_no_routes = s->config->network.no_routes_size;
	}

	if (gc->dns == NULL) {
		gc->dns = s->config->network.dns;
		gc->n_dns = s->config->network.dns_size;
	}

	if (gc->nbns == NULL) {
		gc->nbns = s->config->network.nbns;
		gc->n_nbns = s->config->network.nbns_size;
	}

	if (!gc->has_interim_update_secs) {
		gc->interim_update_secs = s->config->stats_report_time;
		gc->has_interim_update_secs = 1;
	}

	if (!gc->has_session_timeout_secs) {
		gc->session_timeout_secs = s->config->session_timeout;
		gc->has_session_timeout_secs = 1;
	}

	if (!gc->has_deny_roaming) {
		gc->deny_roaming = s->config->deny_roaming;
		gc->has_deny_roaming = 1;
	}

	if (!gc->ipv4_net) {
		gc->ipv4_net = s->config->network.ipv4_network;
	}

	if (!gc->ipv4_netmask) {
		gc->ipv4_netmask = s->config->network.ipv4_netmask;
	}

	if (!gc->ipv6_net) {
		gc->ipv6_net = s->config->network.ipv6_network;
	}

	if (!gc->has_ipv6_prefix) {
		gc->ipv6_prefix = s->config->network.ipv6_prefix;
		gc->has_ipv6_prefix = 1;
	}

	if (!gc->has_ipv6_subnet_prefix) {
		gc->ipv6_subnet_prefix = s->config->network.ipv6_subnet_prefix;
		gc->has_ipv6_subnet_prefix = 1;
	}

	if (!gc->cgroup) {
		gc->cgroup = s->config->cgroup;
	}

	if (!gc->xml_config_file) {
		gc->xml_config_file = s->config->xml_config_file;
	}

	if (!gc->has_rx_per_sec) {
		gc->rx_per_sec = s->config->rx_per_sec;
		gc->has_rx_per_sec = 1;
	}

	if (!gc->has_tx_per_sec) {
		gc->tx_per_sec = s->config->tx_per_sec;
		gc->has_tx_per_sec = 1;
	}

	if (!gc->has_net_priority) {
		gc->net_priority = s->config->net_priority;
		gc->has_net_priority = 1;
	}

	if (!gc->has_keepalive) {
		gc->keepalive = s->config->keepalive;
		gc->has_keepalive = 1;
	}

	if (!gc->has_dpd) {
		gc->dpd = s->config->dpd;
		gc->has_dpd = 1;
	}

	if (!gc->has_mobile_dpd) {
		gc->mobile_dpd = s->config->mobile_dpd;
		gc->has_mobile_dpd = 1;
	}

	if (!gc->has_max_same_clients) {
		gc->max_same_clients = s->config->max_same_clients;
		gc->has_max_same_clients = 1;
	}

	if (!gc->has_tunnel_all_dns) {
		gc->tunnel_all_dns = s->config->tunnel_all_dns;
		gc->has_tunnel_all_dns = 1;
	}

	if (!gc->has_restrict_user_to_routes) {
		gc->restrict_user_to_routes = s->config->restrict_user_to_routes;
		gc->has_restrict_user_to_routes = 1;
	}

	if (!gc->has_mtu) {
		gc->mtu = s->config->network.mtu;
		gc->has_mtu = 1;
	}

	if (!gc->has_idle_timeout) {
		gc->idle_timeout = s->config->idle_timeout;
		gc->has_idle_timeout = 1;
	}

	if (!gc->has_mobile_idle_timeout) {
		gc->mobile_idle_timeout = s->config->mobile_idle_timeout;
		gc->has_mobile_idle_timeout = 1;
	}

	if (gc->n_fw_ports == 0 && s->config->n_fw_ports > 0) {
		gc->n_fw_ports = s->config->n_fw_ports;
		gc->fw_ports = s->config->fw_ports;
	}

	/* since we keep pointers on s->config, increase its usage count */
	proc->config_usage_count = s->config->usage_count;
	(*proc->config_usage_count)++;
}

int session_open(main_server_st * s, struct proc_st *proc, const uint8_t *cookie, unsigned cookie_size)
{
	int ret, e;
	SecAuthSessionMsg ireq = SEC_AUTH_SESSION_MSG__INIT;
	SecAuthSessionReplyMsg *msg = NULL;
	char str_ipv4[MAX_IP_STR];
	char str_ipv6[MAX_IP_STR];

	ireq.uptime = time(0)-proc->conn_time;
	ireq.has_uptime = 1;
	ireq.bytes_in = proc->bytes_in;
	ireq.has_bytes_in = 1;
	ireq.bytes_out = proc->bytes_out;
	ireq.has_bytes_out = 1;
	ireq.sid.data = proc->sid;
	ireq.sid.len = sizeof(proc->sid);

	if (proc->ipv4 && 
	    human_addr2((struct sockaddr *)&proc->ipv4->rip, proc->ipv4->rip_len,
	    str_ipv4, sizeof(str_ipv4), 0) != NULL) {
		ireq.ipv4 = str_ipv4;
	}

	if (proc->ipv6 && 
	    human_addr2((struct sockaddr *)&proc->ipv6->rip, proc->ipv6->rip_len,
	    str_ipv6, sizeof(str_ipv6), 0) != NULL) {
		ireq.ipv6 = str_ipv6;
	}

	if (cookie) {
		ireq.cookie.data = (void*)cookie;
		ireq.cookie.len = cookie_size;
		ireq.has_cookie = 1;
	}

	mslog(s, proc, LOG_DEBUG, "sending msg %s to sec-mod", cmd_request_to_str(SM_CMD_AUTH_SESSION_OPEN));

	ret = send_msg(proc, s->sec_mod_fd_sync, SM_CMD_AUTH_SESSION_OPEN,
		&ireq, (pack_size_func)sec_auth_session_msg__get_packed_size,
		(pack_func)sec_auth_session_msg__pack);
	if (ret < 0) {
		mslog(s, proc, LOG_ERR,
		      "error sending message to sec-mod cmd socket");
		return -1;
	}

	ret = recv_msg(proc, s->sec_mod_fd_sync, SM_CMD_AUTH_SESSION_REPLY,
	       (void *)&msg, (unpack_func) sec_auth_session_reply_msg__unpack, MAIN_SEC_MOD_TIMEOUT);
	if (ret < 0) {
		e = errno;
		mslog(s, proc, LOG_ERR, "error receiving auth reply message from sec-mod cmd socket: %s", strerror(e));
		return ret;
	}

	if (msg->reply != AUTH__REP__OK) {
		mslog(s, proc, LOG_INFO, "could not initiate session for '%s'", proc->username);
		return -1;
	}

	if (msg->config == NULL) {
		mslog(s, proc, LOG_INFO, "received invalid configuration for '%s'; could not initiate session", proc->username);
		return -1;
	}

	proc->config = msg->config;

	apply_default_config(s, proc, proc->config);

	return 0;
}

int session_close(main_server_st * s, struct proc_st *proc)
{
	int ret, e;
	SecAuthSessionMsg ireq = SEC_AUTH_SESSION_MSG__INIT;
	CliStatsMsg *msg = NULL;
	PROTOBUF_ALLOCATOR(pa, proc);

	ireq.uptime = time(0)-proc->conn_time;
	ireq.has_uptime = 1;
	ireq.bytes_in = proc->bytes_in;
	ireq.has_bytes_in = 1;
	ireq.bytes_out = proc->bytes_out;
	ireq.has_bytes_out = 1;
	ireq.sid.data = proc->sid;
	ireq.sid.len = sizeof(proc->sid);

	mslog(s, proc, LOG_DEBUG, "sending msg %s to sec-mod", cmd_request_to_str(SM_CMD_AUTH_SESSION_CLOSE));

	ret = send_msg(proc, s->sec_mod_fd_sync, SM_CMD_AUTH_SESSION_CLOSE,
		&ireq, (pack_size_func)sec_auth_session_msg__get_packed_size,
		(pack_func)sec_auth_session_msg__pack);
	if (ret < 0) {
		mslog(s, proc, LOG_ERR,
		      "error sending message to sec-mod cmd socket");
		return -1;
	}

	ret = recv_msg(proc, s->sec_mod_fd_sync, SM_CMD_AUTH_CLI_STATS,
	       (void *)&msg, (unpack_func) cli_stats_msg__unpack, MAIN_SEC_MOD_TIMEOUT);
	if (ret < 0) {
		e = errno;
		mslog(s, proc, LOG_ERR, "error receiving auth cli stats message from sec-mod cmd socket: %s", strerror(e));
		return ret;
	}

	proc->bytes_in = msg->bytes_in;
	proc->bytes_out = msg->bytes_out;
	if (msg->has_secmod_client_entries)
		s->secmod_client_entries = msg->secmod_client_entries;
	if (msg->has_discon_reason)
		proc->discon_reason = msg->discon_reason;

	cli_stats_msg__free_unpacked(msg, &pa);

	return 0;
}
