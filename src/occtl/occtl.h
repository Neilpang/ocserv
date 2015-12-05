#ifndef OCCTL_H
# define OCCTL_H

#include <stdlib.h>
#include <time.h>
#include "common.h"

#ifdef HAVE_ORIG_READLINE
# include <readline/readline.h>
# include <readline/history.h>
#else
# include <readline.h>
#endif

#define DATE_TIME_FMT "%Y-%m-%d %H:%M"
#define MAX_TMPSTR_SIZE 64

#define NO_JSON(params) (!params || !params->json)
#define HAVE_JSON(params) (params && params->json)

typedef struct cmd_params_st {
	unsigned json;
	unsigned no_pager;
} cmd_params_st;

FILE* pager_start(cmd_params_st *params);
void pager_stop(FILE* fp);
void print_time_ival7(char output[MAX_TMPSTR_SIZE], time_t t1, time_t t2);
void print_iface_stats(const char *iface, time_t since, FILE * out, cmd_params_st *params, unsigned have_more);
int print_list_entries(FILE* out, cmd_params_st *params, const char* name, char **val, unsigned vsize, unsigned have_more);
void print_start_block(FILE *out, cmd_params_st *params);
void print_end_block(FILE *out, cmd_params_st *params, unsigned have_more);
void print_array_block(FILE *out, cmd_params_st *params);
void print_end_array_block(FILE *out, cmd_params_st *params);
void print_separator(FILE *out, cmd_params_st *params);
void print_single_value(FILE *out, cmd_params_st *params, const char *name, const char *value, unsigned have_more);
void print_single_value_int(FILE *out, cmd_params_st *params, const char *name, long i, unsigned have_more);
void print_single_value_ex(FILE *out, cmd_params_st *params, const char *name, const char *value, const char *ex, unsigned have_more);
void print_pair_value(FILE *out, cmd_params_st *params, const char *name1, const char *value1, const char *name2, const char *value2, unsigned have_more);


void
bytes2human(unsigned long bytes, char* output, unsigned output_size, const char* suffix);

char* search_for_id(unsigned idx, const char* match, int match_size);
char* search_for_user(unsigned idx, const char* match, int match_size);
void entries_add(void *pool, const char* user, unsigned user_size, unsigned id);
void entries_clear(void);

char* search_for_ip(unsigned idx, const char* match, int match_size);
void ip_entries_add(void *pool, const char* ip, unsigned ip_size);
void ip_entries_clear(void);

#define DEFAULT_TIMEOUT (10*1000)
#define NO_GROUP "(none)"
#define NO_USER "(none)"

#define ERR_SERVER_UNREACHABLE "could not send message; possibly insufficient permissions or server is offline.\n"

unsigned need_help(const char *arg);
unsigned check_cmd_help(const char *line);

#ifdef HAVE_DBUS
# include <dbus/dbus.h>
# define CONN_TYPE struct dbus_ctx
#else
# define CONN_TYPE struct unix_ctx
#endif

CONN_TYPE *conn_init(void *pool, const char *socket_file);
void conn_close(CONN_TYPE*);

int conn_prehandle(CONN_TYPE *ctx);
void conn_posthandle(CONN_TYPE *ctx);

typedef int (*cmd_func) (CONN_TYPE * conn, const char *arg, cmd_params_st *params);

int handle_status_cmd(CONN_TYPE * conn, const char *arg, cmd_params_st *params);
int handle_list_users_cmd(CONN_TYPE * conn, const char *arg, cmd_params_st *params);
int handle_list_banned_ips_cmd(CONN_TYPE * conn, const char *arg, cmd_params_st *params);
int handle_list_banned_points_cmd(CONN_TYPE * conn, const char *arg, cmd_params_st *params);
int handle_show_user_cmd(CONN_TYPE * conn, const char *arg, cmd_params_st *params);
int handle_show_id_cmd(CONN_TYPE * conn, const char *arg, cmd_params_st *params);
int handle_disconnect_user_cmd(CONN_TYPE * conn, const char *arg, cmd_params_st *params);
int handle_unban_ip_cmd(CONN_TYPE * conn, const char *arg, cmd_params_st *params);
int handle_disconnect_id_cmd(CONN_TYPE * conn, const char *arg, cmd_params_st *params);
int handle_reload_cmd(CONN_TYPE * conn, const char *arg, cmd_params_st *params);
int handle_stop_cmd(CONN_TYPE * conn, const char *arg, cmd_params_st *params);
int handle_events_cmd(struct unix_ctx *ctx, const char *arg, cmd_params_st *params);

#endif
