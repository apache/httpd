
#ifndef SERVICE_H
#define SERVICE_H

#ifdef WIN32
int service_main(int (*main_fn)(int, char **), int argc, char **argv);
int service95_main(int (*main_fn)(int, char **), int argc, char **argv);
void service_set_status(int status);
void service_cd();
BOOL isProcessService();
BOOL isValidService(char *display_name);
void InstallService(char *display_name, char *conf);
void RemoveService(char *display_name);
int service_init();
int send_signal_to_service(char *display_name, char *sig);
void ap_control_handler_terminate(void);
BOOL CALLBACK ap_control_handler(DWORD ctrl_type);
BOOL isWindowsNT(void);
DWORD WINAPI WatchWindow(void *kill_on_logoff);
#endif /* WIN32 */

#endif /* SERVICE_H */
