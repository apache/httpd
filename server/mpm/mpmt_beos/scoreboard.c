#include "httpd.h"
#include "http_log.h"
#include "http_main.h"
#include "http_core.h"
#include "http_config.h"
#include "mpm_status.h"
#include "beosd.h"
#include "http_conf_globals.h"
#include "mpmt_beos.h"
#include "scoreboard.h"

scoreboard *ap_scoreboard_image = NULL;
extern ap_context_t * pconf;
static int maintain_connection_status = 1;

void reinit_scoreboard(ap_context_t *p)
{
    ap_assert(!ap_scoreboard_image);
    ap_scoreboard_image = (scoreboard *) malloc(SCOREBOARD_SIZE);
    if (ap_scoreboard_image == NULL) {
        fprintf(stderr, "Ouch! Out of memory reiniting scoreboard!\n");
    }
    memset(ap_scoreboard_image, 0, SCOREBOARD_SIZE);
}

void cleanup_scoreboard(void)
{
    ap_assert(ap_scoreboard_image);
    free(ap_scoreboard_image);
    ap_scoreboard_image = NULL;
}

API_EXPORT(int) ap_exists_scoreboard_image(void)
{
    return (ap_scoreboard_image ? 1 : 0);
}


void ap_update_connection_status(long conn_id, const char *key,
                                 const char *value)
{
    int i = 0;
    status_table_entry *ss;

    if (!maintain_connection_status) return;
    while (i < STATUSES_PER_CONNECTION) {
        ss = &(ap_scoreboard_image->table[conn_id][i]);
        if (ss->key[0] == '\0') {
            break;
        }
        if (0 == strcmp(ss->key, key)) {
            ap_cpystrn(ss->value, value, VALUE_LENGTH);
            return;
        }
	i++;
    }
    if (i >= STATUSES_PER_CONNECTION) {
        return;
    }
    ap_cpystrn(ss->key, key, KEY_LENGTH);
    ap_cpystrn(ss->value, value, VALUE_LENGTH);
    return;
}

void ap_reset_connection_status(long conn_id)
{
    if (maintain_connection_status) {
        ap_mpmt_beos_force_reset_connection_status(conn_id);
    }
}

void ap_mpmt_beos_set_maintain_connection_status(int flag) {
    maintain_connection_status = flag;
    return;
}

void ap_mpmt_beos_force_reset_connection_status(long conn_id)
{
    int i;

    for (i = 0; i < STATUSES_PER_CONNECTION; i++) {
        ap_scoreboard_image->table[conn_id][i].key[0] = '\0';
    }
}

const char *ap_get_connection_status(long conn_id, const char *key)
{
    int i = 0;
    status_table_entry *ss;

    if (!maintain_connection_status) return "";
    while (i < STATUSES_PER_CONNECTION) {
        ss = &(ap_scoreboard_image->table[conn_id][i]);
        if (ss->key[0] == '\0') {
            break;
        }
        if (0 == strcmp(ss->key, key)) {
            return ss->value;
        }
    }

    return NULL;
}

ap_array_header_t *ap_get_connections(ap_context_t *p)
{
    int i;
    ap_array_header_t *connection_list;
    long *array_slot;

    connection_list = ap_make_array(p, 0, sizeof(long));
    for (i = 0; i < max_daemons_limit*HARD_THREAD_LIMIT; i++) {
	if (ap_scoreboard_image->table[i][0].key[0] != '\0') {
            array_slot = ap_push_array(connection_list);
            *array_slot = i;
        }
    }
    return connection_list;
}

ap_array_header_t *ap_get_connection_keys(ap_context_t *p, long conn_id)
{
    int i = 0;
    status_table_entry *ss;
    ap_array_header_t *key_list;
    char **array_slot;

    key_list = ap_make_array(p, 0, KEY_LENGTH * sizeof(char));
    while (i < STATUSES_PER_CONNECTION) {
        ss = &(ap_scoreboard_image->table[conn_id][i]);
        if (ss->key[0] == '\0') {
            break;
        }
        array_slot = ap_push_array(key_list);
        *array_slot = ap_pstrdup(p, ss->key);
        i++;
    }
    return key_list;
}

ap_array_header_t *ap_get_status_table(ap_context_t *p)
{
    int i, j;
    ap_array_header_t *server_status;
    ap_status_table_row_t *array_slot;
    status_table_entry *ss;

    server_status = ap_make_array(p, 0, sizeof(ap_status_table_row_t));

    for (i = 0; i < max_daemons_limit*HARD_THREAD_LIMIT; i++) {
	if (ap_scoreboard_image->table[i][0].key[0] == '\0')
	    continue;
        array_slot = ap_push_array(server_status);
        array_slot->data = ap_make_table(p, 0);
        array_slot->conn_id = i;
        
        for (j = 0; j < STATUSES_PER_CONNECTION; j++) {
	    ss = &(ap_scoreboard_image->table[i][j]);
            if (ss->key[0] != '\0') {
                ap_table_add(array_slot->data, ss->key, ss->value);
            }
            else {
                break;
            }
        }
    }
    return server_status;
}
