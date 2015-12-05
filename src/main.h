/*
 * Copyright (C) 2013 Nikos Mavrogiannopoulos
 * Copyright (C) 2015 Red Hat, Inc.
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of ocserv.
 *
 * The GnuTLS is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 */
#ifndef MAIN_H
# define MAIN_H

#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <net/if.h>
#include <vpn.h>
#include <tlslib.h>
#include "ipc.pb-c.h"
#include <common.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <ev.h>

#if defined(__FreeBSD__) || defined(__OpenBSD__)
# include <limits.h>
# define SOL_IP IPPROTO_IP
#endif

#define COOKIE_KEY_SIZE 16

extern int saved_argc;
extern char **saved_argv;

extern struct ev_loop *loop;
extern ev_timer maintainance_watcher;

#define MAIN_MAINTAINANCE_TIME (900)

extern sigset_t sig_default_set;
int cmd_parser (void *pool, int argc, char **argv, struct perm_cfg_st** config);
void reload_cfg_file(void *pool, struct perm_cfg_st* config, unsigned archive);
void clear_old_configs(struct perm_cfg_st* config);
void clear_cfg(struct perm_cfg_st* config);
void write_pid_file(void);
void remove_pid_file(void);

struct listener_st {
	ev_io io;
	struct list_node list;
	int fd;
	sock_type_t sock_type;

	struct sockaddr_storage addr; /* local socket address */
	socklen_t addr_len;
	int family;
	int protocol;
};

struct listen_list_st {
	struct list_head head;
	unsigned int total;
};

struct script_wait_st {
	/* so that this structure can behave as ev_child */
	struct ev_child ev_child;

	struct list_node list;

	pid_t pid;
	unsigned int up; /* connect or disconnect script */
	struct proc_st* proc;
};

enum {
	PS_AUTH_INACTIVE, /* no comm with worker */
	PS_AUTH_FAILED, /* no tried authenticated but failed */
	PS_AUTH_INIT, /* worker has sent an auth init msg */
	PS_AUTH_CONT, /* worker has sent an auth cont msg */
	PS_AUTH_COMPLETED /* successful authentication */
};

/* Each worker process maps to a unique proc_st structure.
 */
typedef struct proc_st {
	/* This is first so this structure can behave as an ev_io */
	struct ev_io io;
	struct ev_child ev_child;

	struct list_node list;
	int fd; /* the command file descriptor */
	pid_t pid;
	time_t udp_fd_receive_time; /* when the corresponding process has received a UDP fd */
	
	time_t conn_time; /* the time the user connected */

	/* the tun lease this process has */
	struct tun_lease_st tun_lease;
	struct ip_lease_st *ipv4;
	struct ip_lease_st *ipv6;
	unsigned leases_in_use; /* someone else got our IP leases */

	struct sockaddr_storage remote_addr; /* peer address */
	socklen_t remote_addr_len;
	struct sockaddr_storage our_addr; /* our address */
	socklen_t our_addr_len;

	/* The SID present in the cookie. Used for session control only */
	uint8_t sid[SID_SIZE];
	unsigned active_sid;

	/* The DTLS session ID associated with the TLS session 
	 * it is either generated or restored from a cookie.
	 */
	uint8_t dtls_session_id[GNUTLS_MAX_SESSION_ID];
	unsigned dtls_session_id_size; /* would act as a flag if session_id is set */
	
	/* The following are set by the worker process (or by a stored cookie) */
	char username[MAX_USERNAME_SIZE]; /* the owner */
	char groupname[MAX_GROUPNAME_SIZE]; /* the owner's group */
	char hostname[MAX_HOSTNAME_SIZE]; /* the requested hostname */

	/* the following are copied here from the worker process for reporting
	 * purposes (from main-ctl-handler). */
	char user_agent[MAX_AGENT_NAME];
	char tls_ciphersuite[MAX_CIPHERSUITE_NAME];
	char dtls_ciphersuite[MAX_CIPHERSUITE_NAME];
	char cstp_compr[8];
	char dtls_compr[8];
	unsigned mtu;

	/* if the session is initiated by a cookie the following two are set
	 * and are considered when generating an IP address. That is used to
	 * generate the same address as previously allocated.
	 */
	uint8_t ipv4_seed[4];

	unsigned status; /* PS_AUTH_ */
	unsigned resume_reqs; /* the number of requests received */

	/* these are filled in after the worker process dies, using the
	 * Cli stats message. */
	uint64_t bytes_in;
	uint64_t bytes_out;
	
	unsigned applied_iroutes; /* whether the iroutes in the config have been successfully applied */

	/* The following we rely on talloc for deallocation */
	GroupCfgSt *config; /* custom user/group config */
	int *config_usage_count; /* points to s->config->usage_count */
} proc_st;

struct ip_lease_db_st {
	struct htable ht;
};

struct proc_list_st {
	struct list_head head;
	unsigned int total;
};

struct script_list_st {
	struct list_head head;
};

struct proc_hash_db_st {
	struct htable *db_ip;
	struct htable *db_dtls_id;
	struct htable *db_sid;
	unsigned total;
};

typedef struct main_server_st {
	struct cfg_st *config; /* pointer inside perm_config */
	struct perm_cfg_st *perm_config;
	
	struct ip_lease_db_st ip_leases;

	tls_sess_db_st tls_db;
	struct htable *ban_db;

	tls_st *creds;
	
	uint8_t cookie_key[COOKIE_KEY_SIZE];
	/* when we rotate keys, key the previous one active for verification */
	uint8_t prev_cookie_key[COOKIE_KEY_SIZE];
	unsigned prev_cookie_key_active;

	struct listen_list_st listen_list;
	struct proc_list_st proc_list;
	struct script_list_st script_list;
	/* maps DTLS session IDs to proc entries */
	struct proc_hash_db_st proc_table;
	
	char socket_file[_POSIX_PATH_MAX];
	char full_socket_file[_POSIX_PATH_MAX];
	pid_t sec_mod_pid;

	struct sockaddr_un secmod_addr;
	unsigned secmod_addr_len;
	
	unsigned active_clients;
	/* updated on the cli_stats_msg from sec-mod. 
	 * Holds the number of entries in secmod list of users */
	unsigned secmod_client_entries;
	time_t start_time;

	void * auth_extra;

	/* This one is on worker pool */
	struct worker_st *ws;

	int ctl_fd;

	int sec_mod_fd; /* messages are sent and received async */
	int sec_mod_fd_sync; /* messages are send in a sync order (ping-pong). Only main sends. */
	void *main_pool; /* talloc main pool */
} main_server_st;

void clear_lists(main_server_st *s);

int handle_worker_commands(main_server_st *s, struct proc_st* cur);
int handle_sec_mod_commands(main_server_st *s);

int user_connected(main_server_st *s, struct proc_st* cur);
void user_disconnected(main_server_st *s, struct proc_st* cur);

void expire_tls_sessions(main_server_st *s);

int send_udp_fd(main_server_st* s, struct proc_st * proc, int fd);

int handle_resume_delete_req(main_server_st* s, struct proc_st * proc,
  			   const SessionResumeFetchMsg * req);

int handle_resume_fetch_req(main_server_st* s, struct proc_st * proc,
  			   const SessionResumeFetchMsg * req, 
  			   SessionResumeReplyMsg* rep);

int handle_resume_store_req(main_server_st* s, struct proc_st *proc,
  			   const SessionResumeStoreReqMsg *);

int session_open(main_server_st * s, struct proc_st *proc, const uint8_t *cookie, unsigned cookie_size);
int session_close(main_server_st * s, struct proc_st *proc);

#ifdef DISABLE_LOGS
/* for testing */
# define mslog(...)

#else

void 
__attribute__ ((format(printf, 4, 5)))
    _mslog(const main_server_st * s, const struct proc_st* proc,
    	int priority, const char *fmt, ...);

# ifdef __GNUC__
#  define mslog(s, proc, prio, fmt, ...) \
	(prio==LOG_ERR)?_mslog(s, proc, prio, "%s:%d: "fmt, __FILE__, __LINE__, ##__VA_ARGS__): \
	_mslog(s, proc, prio, fmt, ##__VA_ARGS__)
# else
#  define mslog _mslog
# endif

#endif


void  mslog_hex(const main_server_st * s, const struct proc_st* proc,
    	int priority, const char *prefix, uint8_t* bin, unsigned bin_size, unsigned b64);

int open_tun(main_server_st* s, struct proc_st* proc);
void close_tun(main_server_st* s, struct proc_st* proc);
void reset_tun(struct proc_st* proc);
int set_tun_mtu(main_server_st* s, struct proc_st * proc, unsigned mtu);

int send_cookie_auth_reply(main_server_st* s, struct proc_st* proc,
			AUTHREP r);

int handle_auth_cookie_req(main_server_st* s, struct proc_st* proc,
 			   const AuthCookieRequestMsg * req);

int check_multiple_users(main_server_st *s, struct proc_st* proc);
int handle_script_exit(main_server_st *s, struct proc_st* proc, int code);

int run_sec_mod(main_server_st * s, int *sync_fd);

struct proc_st *new_proc(main_server_st * s, pid_t pid, int cmd_fd,
			struct sockaddr_storage *remote_addr, socklen_t remote_addr_len,
			struct sockaddr_storage *our_addr, socklen_t our_addr_len,
			uint8_t *sid, size_t sid_size);

/* kill the pid */
#define RPROC_KILL 1
/* we are on shutdown, don't wait for anything */
#define RPROC_QUIT (1<<1)

void remove_proc(main_server_st* s, struct proc_st *proc, unsigned flags);
void proc_to_zombie(main_server_st* s, struct proc_st *proc);

inline static void terminate_proc(main_server_st *s, proc_st *proc)
{
	/* if it has an IP, send a signal so that we cleanup
	 * and get stats properly */
	if (proc->pid != -1 && proc->pid != 0)
                kill(proc->pid, SIGTERM);
	else
		remove_proc(s, proc, RPROC_KILL);
}

void put_into_cgroup(main_server_st * s, const char* cgroup, pid_t pid);

inline static
int send_msg_to_worker(main_server_st* s, struct proc_st* proc, uint8_t cmd, 
	    const void* msg, pack_size_func get_size, pack_func pack)
{
	mslog(s, proc, LOG_DEBUG, "sending message '%s' to worker", cmd_request_to_str(cmd));
	return send_msg(proc, proc->fd, cmd, msg, get_size, pack);
}

inline static
int send_socket_msg_to_worker(main_server_st* s, struct proc_st* proc, uint8_t cmd, 
		int socketfd, const void* msg, pack_size_func get_size, pack_func pack)
{
	mslog(s, proc, LOG_DEBUG, "sending (socket) message %u to worker", (unsigned)cmd);
	return send_socket_msg(proc, proc->fd, cmd, socketfd, msg, get_size, pack);
}

void request_reload(int signo);
void request_stop(int signo);

const struct auth_mod_st *get_auth_mod(void);
const struct auth_mod_st *get_backup_auth_mod(void);

#endif
