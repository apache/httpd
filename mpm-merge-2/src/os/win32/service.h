
#ifndef SERVICE_H
#define SERVICE_H

#ifdef WIN32
int service_main(int (*main_fn)(int, char **), int argc, char **argv);
void service_set_status(int status);
void service_cd();
BOOL isProcessService();
BOOL isValidService(char *service_name);
void InstallService(char *service_name, char *conf);
void RemoveService(char *service_name);
int service_init();
int send_signal_to_service(char *service_name, char *sig);
#endif /* WIN32 */

#endif /* SERVICE_H */
