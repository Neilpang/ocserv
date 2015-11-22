/*
 * Copyright (C) 2013, 2014, 2015 Nikos Mavrogiannopoulos
 *
 * This file is part of ocserv.
 *
 * ocserv is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * ocserv is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
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
#include <sys/select.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netdb.h>
#include <system.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/un.h>
#include <common.h>
#include <syslog.h>
#include <vpn.h>
#include <sec-mod.h>
#include <tlslib.h>
#include <ipc.pb-c.h>
#include <sec-mod-sup-config.h>
#include <cloexec.h>
#include <ev.h>
#include <ccan/container_of/container_of.h>

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <gnutls/abstract.h>

/* the maximum time a worker may be connected without sending a request */
#define MAX_WORKER_TIME 20

#define MAX_WAIT_SECS 3
#define MAX_PIN_SIZE GNUTLS_PKCS11_MAX_PIN_LEN
#define MAINTAINANCE_TIME 310

struct ev_loop *sm_loop;
ev_io main_watcher;
ev_io worker_watcher;
ev_signal reload_sig_watcher;
ev_signal term_sig_watcher;
ev_timer maintainance_watcher;

struct pin_st {
	char pin[MAX_PIN_SIZE];
	char srk_pin[MAX_PIN_SIZE];
};

static
int pin_callback(void *user, int attempt, const char *token_url,
		 const char *token_label, unsigned int flags, char *pin,
		 size_t pin_max)
{
	struct pin_st *ps = user;
	int srk = 0;
	const char *p;
	unsigned len;

	if (flags & GNUTLS_PIN_FINAL_TRY) {
		syslog(LOG_ERR,
		       "PIN callback: final try before locking; not attempting to unlock");
		return -1;
	}

	if (flags & GNUTLS_PIN_WRONG) {
		syslog(LOG_ERR,
		       "PIN callback: wrong PIN was entered for '%s' (%s)",
		       token_label, token_url);
		return -1;
	}

	if (ps->pin[0] == 0) {
		syslog(LOG_ERR,
		       "PIN required for '%s' but pin-file was not set",
		       token_label);
		return -1;
	}

	if (strcmp(token_url, "SRK") == 0 || strcmp(token_label, "SRK") == 0) {
		srk = 1;
		p = ps->srk_pin;
	} else {
		p = ps->pin;
	}

	if (srk != 0 && ps->srk_pin[0] == 0) {
		syslog(LOG_ERR,
		       "PIN required for '%s' but srk-pin-file was not set",
		       token_label);
		return -1;
	}

	len = strlen(p);
	if (len > pin_max - 1) {
		syslog(LOG_ERR, "Too long PIN (%u chars)", len);
		return -1;
	}

	memcpy(pin, p, len);
	pin[len] = 0;

	return 0;
}

static
int load_pins(struct perm_cfg_st *config, struct pin_st *s)
{
	int fd, ret;

	s->srk_pin[0] = 0;
	s->pin[0] = 0;

	if (config->srk_pin_file != NULL) {
		fd = open(config->srk_pin_file, O_RDONLY);
		if (fd < 0) {
			syslog(LOG_ERR, "could not open SRK PIN file '%s'",
			       config->srk_pin_file);
			return -1;
		}

		ret = read(fd, s->srk_pin, sizeof(s->srk_pin) - 1);
		close(fd);
		if (ret <= 1) {
			syslog(LOG_ERR, "could not read from PIN file '%s'",
			       config->srk_pin_file);
			return -1;
		}

		if (s->srk_pin[ret - 1] == '\n' || s->srk_pin[ret - 1] == '\r')
			s->srk_pin[ret - 1] = 0;
		s->srk_pin[ret] = 0;
	}

	if (config->pin_file != NULL) {
		fd = open(config->pin_file, O_RDONLY);
		if (fd < 0) {
			syslog(LOG_ERR, "could not open PIN file '%s'",
			       config->pin_file);
			return -1;
		}

		ret = read(fd, s->pin, sizeof(s->pin) - 1);
		close(fd);
		if (ret <= 1) {
			syslog(LOG_ERR, "could not read from PIN file '%s'",
			       config->pin_file);
			return -1;
		}

		if (s->pin[ret - 1] == '\n' || s->pin[ret - 1] == '\r')
			s->pin[ret - 1] = 0;
		s->pin[ret] = 0;
	}

	if (config->key_pin != NULL) {
		strlcpy(s->pin, config->key_pin, sizeof(s->pin));
	}

	if (config->srk_pin != NULL) {
		strlcpy(s->srk_pin, config->srk_pin, sizeof(s->srk_pin));
	}

	return 0;
}

static int send_refresh_cookie_key(sec_mod_st * sec, void *key_data, unsigned key_size)
{
	SecRefreshCookieKey msg = SEC_REFRESH_COOKIE_KEY__INIT;
	int ret;

	msg.key.data = key_data;
	msg.key.len = key_size;

	ret = send_msg(sec, sec->cmd_fd, SM_CMD_REFRESH_COOKIE_KEY, &msg,
		       (pack_size_func) sec_refresh_cookie_key__get_packed_size,
		       (pack_func) sec_refresh_cookie_key__pack);
	if (ret < 0) {
		seclog(sec, LOG_WARNING, "sec-mod error in sending cookie key");
	}

	return 0;
}

static int handle_op(void *pool, int cfd, sec_mod_st * sec, uint8_t type, uint8_t * rep,
		     size_t rep_size)
{
	SecOpMsg msg = SEC_OP_MSG__INIT;
	int ret;

	msg.data.data = rep;
	msg.data.len = rep_size;

	ret = send_msg(pool, cfd, type, &msg,
		       (pack_size_func) sec_op_msg__get_packed_size,
		       (pack_func) sec_op_msg__pack);
	if (ret < 0) {
		seclog(sec, LOG_WARNING, "sec-mod error in sending reply");
	}

	return 0;
}

static
int process_packet(void *pool, int cfd, pid_t pid, sec_mod_st * sec, cmd_request_t cmd,
		   uint8_t * buffer, size_t buffer_size)
{
	unsigned i;
	gnutls_datum_t data, out;
	int ret;
	SecOpMsg *op;
	PROTOBUF_ALLOCATOR(pa, pool);

	seclog(sec, LOG_DEBUG, "cmd [size=%d] %s\n", (int)buffer_size,
	       cmd_request_to_str(cmd));
	data.data = buffer;
	data.size = buffer_size;

	switch (cmd) {
	case SM_CMD_SIGN:
	case SM_CMD_DECRYPT:
		op = sec_op_msg__unpack(&pa, data.size, data.data);
		if (op == NULL) {
			seclog(sec, LOG_INFO, "error unpacking sec op\n");
			return -1;
		}

		i = op->key_idx;
		if (op->has_key_idx == 0 || i >= sec->key_size) {
			seclog(sec, LOG_INFO,
			       "received out-of-bounds key index (%d)", i);
			return -1;
		}

		data.data = op->data.data;
		data.size = op->data.len;

		if (cmd == SM_CMD_DECRYPT) {
			ret =
			    gnutls_privkey_decrypt_data(sec->key[i], 0, &data,
							&out);
		} else {
#if GNUTLS_VERSION_NUMBER >= 0x030200
			ret =
			    gnutls_privkey_sign_hash(sec->key[i], 0,
						     GNUTLS_PRIVKEY_SIGN_FLAG_TLS1_RSA,
						     &data, &out);
#else
			ret =
			    gnutls_privkey_sign_raw_data(sec->key[i], 0, &data,
							 &out);
#endif
		}
		sec_op_msg__free_unpacked(op, &pa);

		if (ret < 0) {
			seclog(sec, LOG_INFO, "error in crypto operation: %s",
			       gnutls_strerror(ret));
			return -1;
		}

		ret = handle_op(pool, cfd, sec, cmd, out.data, out.size);
		gnutls_free(out.data);

		return ret;

	case SM_CMD_CLI_STATS:{
			CliStatsMsg *tmsg;

			tmsg = cli_stats_msg__unpack(&pa, data.size, data.data);
			if (tmsg == NULL) {
				seclog(sec, LOG_ERR, "error unpacking data");
				return -1;
			}

			ret = handle_sec_auth_stats_cmd(sec, tmsg);
			cli_stats_msg__free_unpacked(tmsg, &pa);
			return ret;
		}
		break;

	case SM_CMD_AUTH_INIT:{
			SecAuthInitMsg *auth_init;

			auth_init =
			    sec_auth_init_msg__unpack(&pa, data.size,
						      data.data);
			if (auth_init == NULL) {
				seclog(sec, LOG_INFO, "error unpacking auth init\n");
				return -1;
			}

			ret = handle_sec_auth_init(cfd, sec, auth_init, pid);
			sec_auth_init_msg__free_unpacked(auth_init, &pa);
			return ret;
		}
	case SM_CMD_AUTH_CONT:{
			SecAuthContMsg *auth_cont;

			auth_cont =
			    sec_auth_cont_msg__unpack(&pa, data.size,
						      data.data);
			if (auth_cont == NULL) {
				seclog(sec, LOG_INFO, "error unpacking auth cont\n");
				return -1;
			}

			ret = handle_sec_auth_cont(cfd, sec, auth_cont);
			sec_auth_cont_msg__free_unpacked(auth_cont, &pa);
			return ret;
		}
	default:
		seclog(sec, LOG_WARNING, "unknown type 0x%.2x", cmd);
		return -1;
	}

	return 0;
}

static
int process_packet_from_main(void *pool, int fd, sec_mod_st * sec, cmd_request_t cmd,
		   uint8_t * buffer, size_t buffer_size)
{
	gnutls_datum_t data;
	int ret;
	PROTOBUF_ALLOCATOR(pa, pool);

	seclog(sec, LOG_DEBUG, "cmd [size=%d] %s\n", (int)buffer_size,
	       cmd_request_to_str(cmd));
	data.data = buffer;
	data.size = buffer_size;

	switch (cmd) {
	case SM_CMD_AUTH_BAN_IP_REPLY:{
		BanIpReplyMsg *msg = NULL;

		msg =
		    ban_ip_reply_msg__unpack(&pa, data.size,
					     data.data);
		if (msg == NULL) {
			seclog(sec, LOG_INFO, "error unpacking auth ban ip reply\n");
			return ERR_BAD_COMMAND;
		}

		handle_sec_auth_ban_ip_reply(sec, msg);
		ban_ip_reply_msg__free_unpacked(msg, &pa);

		return 0;
	}
	case SM_CMD_AUTH_SESSION_OPEN:
	case SM_CMD_AUTH_SESSION_CLOSE:{
			SecAuthSessionMsg *msg;

			msg =
			    sec_auth_session_msg__unpack(&pa, data.size,
						      data.data);
			if (msg == NULL) {
				seclog(sec, LOG_INFO, "error unpacking session close\n");
				return ERR_BAD_COMMAND;
			}

			ret = handle_sec_auth_session_cmd(sec, fd, msg, cmd);
			sec_auth_session_msg__free_unpacked(msg, &pa);

			return ret;
		}
	default:
		seclog(sec, LOG_WARNING, "unknown type 0x%.2x", cmd);
		return ERR_BAD_COMMAND;
	}

	return 0;
}

static void maintainance_watcher_cb(EV_P_ ev_timer *w, int revents)
{
	sec_mod_st *sec = ev_userdata(sm_loop);
	time_t now = time(0);

	seclog(sec, LOG_DEBUG, "performing maintenance");

	if (sec->config->cookie_rekey_time > 0 && now - sec->cookie_key_last_update > sec->config->cookie_rekey_time) {
		uint8_t cookie_key[COOKIE_KEY_SIZE];
		int ret;

		ret = gnutls_rnd(GNUTLS_RND_RANDOM, cookie_key, sizeof(cookie_key));
		if (ret >= 0) {
			if (send_refresh_cookie_key(sec, cookie_key, sizeof(cookie_key)) == 0) {
				sec->cookie_key_last_update = now;
				memcpy(sec->cookie_key, cookie_key, sizeof(cookie_key));
			} else {
				seclog(sec, LOG_ERR, "could not notify main for new cookie key");
			}
		} else {
			seclog(sec, LOG_ERR, "could not refresh cookie key");
		}
	}

	cleanup_client_entries(sec);
	seclog(sec, LOG_DEBUG, "active sessions %d", sec_mod_client_db_elems(sec));
}

static void reload_sig_watcher_cb(struct ev_loop *loop, ev_signal *w, int revents)
{
	sec_mod_st *sec = ev_userdata(loop);

	seclog(sec, LOG_DEBUG, "reloading configuration");
	reload_cfg_file(sec, sec->perm_config);
	sec->config = sec->perm_config->config;
}

static void term_sig_watcher_cb(struct ev_loop *loop, ev_signal *w, int revents)
{
	ev_break (loop, EVBREAK_ALL);
}

static
int serve_request_main(sec_mod_st *sec, void *pool, int fd, uint8_t *buffer, unsigned buffer_size)
{
	int ret, e;
	unsigned cmd, length;
	uint16_t l16;

	/* read request */
	do {
		ret = read(fd, buffer, buffer_size);
	} while(ret == -1 && (errno == EINTR || errno == EAGAIN));

	if (ret == 0)
		goto leave;
	else if (ret < 3) {
		e = errno;
		seclog(sec, LOG_ERR, "error receiving msg head: %s",
		       strerror(e));
		ret = ERR_BAD_COMMAND;
		goto leave;
	}

	cmd = buffer[0];
	memcpy(&l16, &buffer[1], 2);
	length = l16;

	seclog(sec, LOG_DEBUG, "received request %s", cmd_request_to_str(cmd));
	if (cmd <= MIN_SM_MAIN_CMD || cmd >= MAX_SM_MAIN_CMD) {
		seclog(sec, LOG_ERR, "received invalid message from main of %u bytes (cmd: %u)\n",
		      (unsigned)length, (unsigned)cmd);
		return ERR_BAD_COMMAND;
	}

	if (length > buffer_size - 4 || length > ret-3) {
		seclog(sec, LOG_ERR, "invalid message length from main %d, have %d", length, ret-3);
		ret = ERR_BAD_COMMAND;
		goto leave;
	}

	ret = process_packet_from_main(pool, fd, sec, cmd, buffer+3, length);
	if (ret < 0) {
		seclog(sec, LOG_ERR, "error processing data for '%s' command (%d)", cmd_request_to_str(cmd), ret);
	}
	
 leave:
	return ret;
}

static
int serve_request(sec_mod_st *sec, void *pool, int cfd, pid_t pid, uint8_t *buffer, unsigned buffer_size)
{
	int ret, e;
	unsigned cmd, length;
	uint16_t l16;

	/* read request */
	do {
		ret = read(cfd, buffer, buffer_size);
	} while(ret == -1 && (errno == EINTR || errno == EAGAIN));

	if (ret == 0)
		goto leave;
	else if (ret < 3) {
		e = errno;
		seclog(sec, LOG_INFO, "error receiving msg head: %s",
		       strerror(e));
		ret = -1;
		goto leave;
	}

	cmd = buffer[0];
	memcpy(&l16, &buffer[1], 2);
	length = l16;

	if (length > buffer_size - 4 || length > ret-3) {
		seclog(sec, LOG_INFO, "invalid message length %d, have %d", length, ret-3);
		ret = -1;
		goto leave;
	}

	ret = process_packet(pool, cfd, pid, sec, cmd, buffer+3, length);
	if (ret < 0) {
		seclog(sec, LOG_INFO, "error processing data for '%s' command (%d)", cmd_request_to_str(cmd), ret);
	}
	
 leave:
	return ret;
}

static void main_watcher_cb (EV_P_ ev_io *w, int revents)
{
	sec_mod_st *sec = ev_userdata(sm_loop);
	uint8_t *buffer;
	unsigned buffer_size;
	int ret;

	/* we do a new allocation, to also use it as pool for the
	 * parsers to use */
	buffer_size = MAX_MSG_SIZE;
	buffer = talloc_size(sec, buffer_size);
	if (buffer == NULL) {
		seclog(sec, LOG_ERR, "error in memory allocation");
		exit(1);
	}

	ret = serve_request_main(sec, buffer, w->fd, buffer, buffer_size);
	if (ret < 0 && ret == ERR_BAD_COMMAND) {
		seclog(sec, LOG_ERR, "error processing async command from main");
		exit(1);
	}
	talloc_free(buffer);
}

typedef struct worker_request_st {
	ev_io io;
	ev_timer timer;
	pid_t pid;
	int fd;
	unsigned buffer_size;
	uint8_t *buffer;
} worker_request_st;

static void worker_request_watcher_cb (EV_P_ ev_io *w, int revents)
{
	sec_mod_st *sec = ev_userdata(sm_loop);
	worker_request_st *wls = container_of(w, struct worker_request_st, io);

	serve_request(sec, wls, w->fd, wls->pid, wls->buffer, wls->buffer_size);

	ev_io_stop(EV_A_ w);
	ev_timer_stop(EV_A_ &wls->timer);
	close(w->fd);
	talloc_free(wls);
}

static void worker_request_watcher_timeout_cb (EV_P_ ev_timer *w, int revents)
{
	worker_request_st *wls = container_of(w, struct worker_request_st, timer);

	ev_io_stop(EV_A_ &wls->io);
	ev_timer_stop(EV_A_ w);
	close(wls->fd);
	talloc_free(wls);
}

static void worker_watcher_cb (EV_P_ ev_io *w, int revents)
{
	sec_mod_st *sec = ev_userdata(sm_loop);
	struct sockaddr_un sa;
	socklen_t sa_len;
	int cfd, e, ret;
	uid_t uid;
	pid_t pid;
	worker_request_st *wls;

	sa_len = sizeof(sa);
	cfd = accept(w->fd, (struct sockaddr *)&sa, &sa_len);
	if (cfd == -1) {
		e = errno;
		if (e != EINTR) {
			seclog(sec, LOG_DEBUG,
			       "sec-mod error accepting connection: %s",
			       strerror(e));
			return;
		}
	}
	set_cloexec_flag (cfd, 1);

	/* do not allow unauthorized processes to issue commands
	 */
	ret = check_upeer_id("sec-mod", sec->config->debug, cfd, sec->perm_config->uid, sec->perm_config->gid, &uid, &pid);
	if (ret < 0) {
		seclog(sec, LOG_INFO, "rejected unauthorized connection");
		close(cfd);
		return;
	}

	/* we do a new allocation, to also use it as pool for the
	 * parsers to use */
	wls = talloc_size(sec, sizeof(worker_request_st)+MAX_MSG_SIZE);
	if (wls == NULL) {
		seclog(sec, LOG_ERR, "error in memory allocation");
		close(cfd);
		return;
	}

	wls->buffer = ((uint8_t*)wls)+sizeof(worker_request_st);
	wls->buffer_size = MAX_MSG_SIZE;
	wls->fd = cfd;
	wls->pid = pid;

	memset(wls->buffer, 0, wls->buffer_size);
	ev_io_init(&wls->io, worker_request_watcher_cb, cfd, EV_READ);

	ev_init(&wls->timer, worker_request_watcher_timeout_cb);
	ev_timer_set(&wls->timer, MAX_WORKER_TIME, 0);

	ev_io_start(sm_loop, &wls->io);
	ev_timer_start(sm_loop, &wls->timer);

	return;
}


static void syserr_cb(const char *msg)
{
	sec_mod_st *sec = ev_userdata(sm_loop);
	seclog(sec, LOG_ERR, "libev fatal error: %s", msg);
	abort();
}

/* sec_mod_server:
 * @config: server configuration
 * @socket_file: the name of the socket
 * @cmd_fd: socket to exchange commands with main
 * @cmd_fd_sync: socket to received sync commands from main
 *
 * This is the main part of the security module.
 * It creates the unix domain socket identified by @socket_file
 * and then accepts connections from the workers to it. Then 
 * it serves commands requested on the server's private key.
 *
 * When the operation is decrypt the provided data are
 * decrypted and sent back to worker. The sign operation
 * signs the provided data.
 *
 * The security module's reply to the worker has the
 * following format:
 * byte[0-1]: length (uint16_t)
 * byte[2-total]: data (signature or decrypted data)
 *
 * The reason for having this as a separate process
 * is to avoid any bug on the workers to leak the key.
 * It is not part of main because workers are spawned
 * from main, and thus should be prevented from accessing
 * parts the key in stack or heap that was not zeroized.
 * Other than that it allows the main server to spawn
 * clients fast without becoming a bottleneck due to private 
 * key operations.
 */
void sec_mod_server(void *main_pool, struct perm_cfg_st *perm_config, const char *socket_file,
		    uint8_t cookie_key[COOKIE_KEY_SIZE], int cmd_fd, int cmd_fd_sync)
{
	struct sockaddr_un sa;
	int ret, e;
	unsigned i;
	struct pin_st pins;
	int sd;
	sec_mod_st *sec;
	void *sec_mod_pool;

#ifdef DEBUG_LEAKS
	talloc_enable_leak_report_full();
#endif
	sm_loop = EV_DEFAULT;
	if (sm_loop == NULL) {
		seclog(sec, LOG_ERR, "could not initialize event loop");
		exit(1);
	}

	sec_mod_pool = talloc_init("sec-mod");
	if (sec_mod_pool == NULL) {
		seclog(sec, LOG_ERR, "error in memory allocation");
		exit(1);
	}

	sec = talloc_zero(sec_mod_pool, sec_mod_st);
	if (sec == NULL) {
		seclog(sec, LOG_ERR, "error in memory allocation");
		exit(1);
	}

	memcpy(sec->cookie_key, cookie_key, COOKIE_KEY_SIZE);
	sec->dcookie_key.data = sec->cookie_key;
	sec->dcookie_key.size = COOKIE_KEY_SIZE;
	sec->perm_config = talloc_steal(sec, perm_config);
	sec->config = sec->perm_config->config;

	sup_config_init(sec);

	memset(&sa, 0, sizeof(sa));
	sa.sun_family = AF_UNIX;
	strlcpy(sa.sun_path, socket_file, sizeof(sa.sun_path));
	remove(socket_file);

#define SOCKET_FILE sa.sun_path

	/* we no longer need the main pool after this point. */
	talloc_free(main_pool);

	sec_auth_init(sec, perm_config);
	sec->cmd_fd = cmd_fd;
	sec->cmd_fd_sync = cmd_fd_sync;

#ifdef HAVE_PKCS11
	ret = gnutls_pkcs11_reinit();
	if (ret < 0) {
		seclog(sec, LOG_WARNING, "error in PKCS #11 reinitialization: %s",
		       gnutls_strerror(ret));
	}
#endif

	if (sec_mod_client_db_init(sec) == NULL) {
		seclog(sec, LOG_ERR, "error in client db initialization");
		exit(1);
	}

	sd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sd == -1) {
		e = errno;
		seclog(sec, LOG_ERR, "could not create socket '%s': %s", SOCKET_FILE,
		       strerror(e));
		exit(1);
	}
	set_cloexec_flag(sd, 1);

	umask(066);
	ret = bind(sd, (struct sockaddr *)&sa, SUN_LEN(&sa));
	if (ret == -1) {
		e = errno;
		seclog(sec, LOG_ERR, "could not bind socket '%s': %s", SOCKET_FILE,
		       strerror(e));
		exit(1);
	}

	ret = chown(SOCKET_FILE, perm_config->uid, perm_config->gid);
	if (ret == -1) {
		e = errno;
		seclog(sec, LOG_INFO, "could not chown socket '%s': %s", SOCKET_FILE,
		       strerror(e));
	}

	ret = listen(sd, 1024);
	if (ret == -1) {
		e = errno;
		seclog(sec, LOG_ERR, "could not listen to socket '%s': %s",
		       SOCKET_FILE, strerror(e));
		exit(1);
	}

	ret = load_pins(sec->perm_config, &pins);
	if (ret < 0) {
		seclog(sec, LOG_ERR, "error loading PIN files");
		exit(1);
	}

	/* FIXME: the private key isn't reloaded on reload */
	sec->key_size = sec->perm_config->key_size;
	sec->key = talloc_size(sec, sizeof(*sec->key) * sec->perm_config->key_size);
	if (sec->key == NULL) {
		seclog(sec, LOG_ERR, "error in memory allocation");
		exit(1);
	}

	/* read private keys */
	for (i = 0; i < sec->key_size; i++) {
		ret = gnutls_privkey_init(&sec->key[i]);
		GNUTLS_FATAL_ERR(ret);

		/* load the private key */
		if (gnutls_url_is_supported(sec->perm_config->key[i]) != 0) {
			gnutls_privkey_set_pin_function(sec->key[i],
							pin_callback, &pins);
			ret =
			    gnutls_privkey_import_url(sec->key[i],
						      sec->perm_config->key[i], 0);
			GNUTLS_FATAL_ERR(ret);
		} else {
			gnutls_datum_t data;
			ret = gnutls_load_file(sec->perm_config->key[i], &data);
			if (ret < 0) {
				seclog(sec, LOG_ERR, "error loading file '%s'",
				       sec->perm_config->key[i]);
				GNUTLS_FATAL_ERR(ret);
			}

			ret =
			    gnutls_privkey_import_x509_raw(sec->key[i], &data,
							   GNUTLS_X509_FMT_PEM,
							   NULL, 0);
			if (ret == GNUTLS_E_DECRYPTION_FAILED && pins.pin[0]) {
				ret =
				    gnutls_privkey_import_x509_raw(sec->key[i], &data,
								   GNUTLS_X509_FMT_PEM,
								   pins.pin, 0);
			}
			GNUTLS_FATAL_ERR(ret);

			gnutls_free(data.data);
		}
	}

	ev_set_userdata (sm_loop, sec);
	ev_set_syserr_cb(syserr_cb);

	ev_init(&main_watcher, main_watcher_cb);
	ev_io_set(&main_watcher, cmd_fd, EV_READ);
	ev_io_set(&main_watcher, cmd_fd_sync, EV_READ);

	ev_init(&worker_watcher, worker_watcher_cb);
	ev_io_set(&worker_watcher, sd, EV_READ);

	ev_init (&reload_sig_watcher, reload_sig_watcher_cb);
	ev_signal_set (&reload_sig_watcher, SIGHUP);
	ev_signal_start (sm_loop, &reload_sig_watcher);

	ev_init (&term_sig_watcher, term_sig_watcher_cb);
	ev_signal_set (&term_sig_watcher, SIGTERM);
	ev_signal_set (&term_sig_watcher, SIGINT);
	ev_signal_start (sm_loop, &term_sig_watcher);

	ev_init(&maintainance_watcher, maintainance_watcher_cb);
	ev_timer_set(&maintainance_watcher, MAINTAINANCE_TIME, MAINTAINANCE_TIME);
	ev_timer_start(sm_loop, &maintainance_watcher);

	ev_io_start (sm_loop, &main_watcher);
	ev_io_start (sm_loop, &worker_watcher);

	/* sec-mod loop */
	ev_run (sm_loop, 0);

	for (i = 0; i < sec->key_size; i++) {
		gnutls_privkey_deinit(sec->key[i]);
	}

	sec_mod_client_db_deinit(sec);
#ifdef DEBUG_LEAKS
	talloc_report_full(sec, stderr);
#endif
	talloc_free(sec);
}
