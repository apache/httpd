/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2004 The Apache Software Foundation.  All rights
 * reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The end-user documentation included with the redistribution,
 *    if any, must include the following acknowledgment:
 *       "This product includes software developed by the
 *        Apache Software Foundation (http://www.apache.org/)."
 *    Alternately, this acknowledgment may appear in the software itself,
 *    if and wherever such third-party acknowledgments normally appear.
 *
 * 4. The names "Apache" and "Apache Software Foundation" must
 *    not be used to endorse or promote products derived from this
 *    software without prior written permission. For written
 *    permission, please contact apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache",
 *    nor may "Apache" appear in their name, without prior written
 *    permission of the Apache Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 *
 * Portions of this software are based upon public domain software
 * originally written at the National Center for Supercomputing Applications,
 * University of Illinois, Urbana-Champaign.
 */

#ifdef WIN32

#include "ap_config.h"
#include "multithread.h"

#include <process.h>
#include <assert.h>

static int
map_rv(int rv)
{
    switch(rv)
    {
    case WAIT_OBJECT_0:
    case WAIT_ABANDONED:
        return(MULTI_OK);
    case WAIT_TIMEOUT:
        return(MULTI_TIMEOUT);
    case WAIT_FAILED:
        return(MULTI_ERR);
    default:
        assert(0);
    }

    assert(0);
    return(0);
}


thread *
create_thread(void (thread_fn)(void *), void *thread_arg)
{
    int id;
    int rv;
    
    rv = _beginthreadex(NULL, 0, (LPTHREAD_START_ROUTINE)thread_fn,
            thread_arg, 0, &id);

    return((thread *)rv);
}


int
kill_thread(thread *thread_id)
{
    return(TerminateThread(thread_id, 1));
}


int
await_thread(thread *thread_id, int sec_to_wait)
{
    int rv;
    
    rv = WaitForSingleObject(thread_id, sec_to_wait*1000);
    
    return(map_rv(rv));
}

void
exit_thread(int status)
{
    _endthreadex(status);
}

void
free_thread(thread *thread_id)
{
    CloseHandle(thread_id);
}



API_EXPORT(mutex *) ap_create_mutex(char *name)
{
    return(CreateMutex(NULL, FALSE, name));
}

API_EXPORT(mutex *) ap_open_mutex(char *name)
{
    return(OpenMutex(MUTEX_ALL_ACCESS, FALSE, name));
}


API_EXPORT(int) ap_acquire_mutex(mutex *mutex_id)
{
    int rv;
    
    rv = WaitForSingleObject(mutex_id, INFINITE);
    
    return(map_rv(rv));
}

API_EXPORT(int) ap_release_mutex(mutex *mutex_id)
{
    return(ReleaseMutex(mutex_id));
}

API_EXPORT(void) ap_destroy_mutex(mutex *mutex_id)
{
    CloseHandle(mutex_id);
}


semaphore *
create_semaphore(int initial)
{
    return(CreateSemaphore(NULL, initial, 1000000, NULL));
}

int acquire_semaphore(semaphore *semaphore_id)
{
    int rv;
    
    rv = WaitForSingleObject(semaphore_id, INFINITE);
    
    return(map_rv(rv));
}

int release_semaphore(semaphore *semaphore_id)
{
    return(ReleaseSemaphore(semaphore_id, 1, NULL));
}

void destroy_semaphore(semaphore *semaphore_id)
{
    CloseHandle(semaphore_id);
}


event *
create_event(int manual, int initial, char *name)
{
    return(CreateEvent(NULL, manual, initial, name));
}

event *
open_event(char *name)
{
    return(OpenEvent(EVENT_ALL_ACCESS, FALSE, name));
}


int acquire_event(event *event_id)
{
    int rv;
    
    rv = WaitForSingleObject(event_id, INFINITE);
    
    return(map_rv(rv));
}

int set_event(event *event_id)
{
    return(SetEvent(event_id));
}

int reset_event(event *event_id)
{
    return(ResetEvent(event_id));
}


void destroy_event(event *event_id)
{
    CloseHandle(event_id);
}

#else


thread *create_thread(void (thread_fn)(void *thread_arg),
	void *thread_arg)
{
    return(NULL);
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


mutex *ap_create_mutex(char *name)
{
    return(NULL);
}

mutex *ap_open_mutex(char *name)
{
    return(NULL);
}

int ap_acquire_mutex(mutex *mutex_id)
{
    return(0);
}
int ap_release_mutex(mutex *mutex_id)
{
    return(0);
}
void ap_destroy_mutex(mutex *mutex_id)
{}


semaphore *create_semaphore(int initial)
{
    return(NULL);
}
int acquire_semaphore(semaphore *semaphore_id)
{
    return(0);
}
int release_semaphore(semaphore *semaphore_id)
{
    return(0);
}
void destroy_semaphore(semaphore *semaphore_id)
{}

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


#endif /* WIN32 */

