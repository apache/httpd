#include "httpd.h"
#include "http_log.h"
#include "http_main.h"
#include "http_core.h"
#include "http_config.h"
#include "unixd.h"
#include "http_conf_globals.h"
#include "dexter.h"
#include "scoreboard.h"

scoreboard ap_scoreboard_image[HARD_SERVER_LIMIT];

void reinit_scoreboard(pool *p)
{
    int i;

    for (i = 0; i < HARD_SERVER_LIMIT; i++) {
        ap_scoreboard_image[i].status = SERVER_DEAD;
        ap_scoreboard_image[i].pid = 0;
    }
}

API_EXPORT(int) find_child_by_pid(int pid)
{
    int i;

    for (i = 0; i < max_daemons_limit; ++i)
	if (ap_scoreboard_image[i].pid == pid)
	    return i;

    return -1;
}

int ap_update_child_status(int child_num, int status)
{
    int old_status;

    if (child_num < 0)
	return -1;

    old_status = ap_scoreboard_image[child_num].status;
    ap_scoreboard_image[child_num].status = status;

    return old_status;
}
