
#ifndef SERVICE_H
#define SERVICE_H

#ifdef WIN32

/* BIG RED WARNING: exit() is mapped to allow us to capture the exit
 * status.  This header must only be included from modules linked into
 * the ApacheCore.dll - since it's a horrible behavior to exit() from
 * any module outside the main() block, and we -will- assume it's a
 * fatal error.  No dynamically linked module will ever be able to find
 * the real_exit_code, and _will_ GP fault if it tries this macro.
 */

#define exit(status) ((exit)(real_exit_code ? (real_exit_code = (status)) : (status)))
extern int real_exit_code;
void hold_console_open_on_error(void);

int service_main(int (*main_fn)(int, char **), int argc, char **argv);
int service95_main(int (*main_fn)(int, char **), int argc, char **argv,
		   char *display_name);
void service_set_status(int status);
void service_cd();
BOOL isProcessService();
BOOL isValidService(char *display_name);
void InstallService(char *display_name, char *conf);
void RemoveService(char *display_name);
int service_init();
int send_signal_to_service(char *display_name, char *sig);
BOOL isWindowsNT(void);
void ap_start_console_monitor(void);
#endif /* WIN32 */

#endif /* SERVICE_H */
