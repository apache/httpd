
#ifndef SERVICE_H
#define SERVICE_H

#ifdef WIN32
int service_main(int (*main_fn)(int, char **), int argc, char **argv,
                  char *service_name,
                  int install_flag, int run_as_service);
void service_set_status(int status);
void service_cd();
#endif /* WIN32 */

#endif /* SERVICE_H */
