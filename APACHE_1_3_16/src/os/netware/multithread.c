
#include "ap_config.h"
#include "httpd.h"
#include "http_conf_globals.h"
#include "multithread.h"
#include <nwsemaph.h>


thread *create_thread(void (thread_fn)(void *), void *thread_arg)
{
    int rv;

    rv = BeginThreadGroup(thread_fn, NULL, ap_thread_stack_size, thread_arg);
    return((thread *)rv);
}

int kill_thread(thread *thread_id)
{
    return(0);
}

int await_thread(thread *thread_id, int sec_to_wait)
{
    return(0);
}

void exit_thread(int status)
{}

void free_thread(thread *thread_id)
{}


mutex * ap_create_mutex(char *name)
{
    return (mutex*)kMutexAlloc(name);
}

mutex * ap_open_mutex(char *name)
{
	return(NULL);
}

int ap_acquire_mutex(mutex *mutex_id)
{
    return(kMutexLock(mutex_id));
}

int ap_release_mutex(mutex *mutex_id)
{
    if (kMutexUnlock(mutex_id))
        return 0;
    else
        return 1;
}

void ap_destroy_mutex(mutex *mutex_id)
{
    kMutexFree(mutex_id);
}


semaphore *create_semaphore(int initial)
{
	return((semaphore*)OpenLocalSemaphore(initial));
}
int acquire_semaphore(semaphore *semaphore_id)
{
	return(WaitOnLocalSemaphore((long)semaphore_id));
}
int release_semaphore(semaphore *semaphore_id)
{
	return(SignalLocalSemaphore((long)semaphore_id));
}
void destroy_semaphore(semaphore *semaphore_id)
{
	CloseLocalSemaphore((long)semaphore_id);
}

event *create_event(int manual, int initial, char *name)
{
    return(NULL);
}
event *open_event(char *name)
{
    return(NULL);
}
int acquire_event(event *event_id)
{
    return(0);
}
int set_event(event *event_id)
{
    return(0);
}
int reset_event(event *event_id)
{
    return(0);
}
void destroy_event(event *event_id)
{}



