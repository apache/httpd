#ifndef MULTITHREAD_H
#define MULTITHREAD_H

#include "conf.h"

#define MULTI_OK (0)
#define MULTI_TIMEOUT (1)
#define MULTI_ERR (2)

/*
 * Ambarish: Need to do the right stuff on multi-threaded unix
 * I believe this is terribly ugly
 */
#ifndef MULTITHREAD
#define __declspec( thread )
#endif /* ndef MULTITHREAD */

typedef void mutex;
typedef void semaphore;
typedef void thread;
typedef void event;


thread *create_thread(void (thread_fn)(void *thread_arg), void *thread_arg);
int kill_thread(thread *thread_id);
int await_thread(thread *thread_id, int sec_to_wait);
void exit_thread(int status);
void free_thread(thread *thread_id);


mutex *create_mutex(char *name);
mutex *open_mutex(char *name);
int acquire_mutex(mutex *mutex_id);
int release_mutex(mutex *mutex_id);
void destroy_mutex(mutex *mutex_id);


semaphore *create_semaphore(int initial);
int acquire_semaphore(semaphore *semaphore_id);
int release_semaphore(semaphore *semaphore_id);
void destroy_semaphore(semaphore *semaphore_id);

event *create_event(int manual, int initial, char *name);
event *open_event(char *name);
int acquire_event(event *event_id);
int set_event(event *event_id);
int reset_event(event *event_id);
void destroy_event(event *event_id);

#endif /* ndef MULTITHREAD_H */

