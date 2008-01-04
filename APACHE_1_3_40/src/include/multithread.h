/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef APACHE_MULTITHREAD_H
#define APACHE_MULTITHREAD_H

#ifdef __cplusplus
extern "C" {
#endif

#define MULTI_OK (0)
#define MULTI_TIMEOUT (1)
#define MULTI_ERR (2)

typedef void mutex;
typedef void semaphore;
typedef void thread;
typedef void event;

/*
 * Ambarish: Need to do the right stuff on multi-threaded unix
 * I believe this is terribly ugly
 */
#ifdef MULTITHREAD
#ifdef NETWARE
#define APACHE_TLS
#else
#define APACHE_TLS __declspec( thread )
#endif

thread *create_thread(void (thread_fn) (void *thread_arg), void *thread_arg);
int kill_thread(thread *thread_id);
int await_thread(thread *thread_id, int sec_to_wait);
void exit_thread(int status);
void free_thread(thread *thread_id);

API_EXPORT(mutex *) ap_create_mutex(char *name);
API_EXPORT(mutex *) ap_open_mutex(char *name);
API_EXPORT(int) ap_acquire_mutex(mutex *mutex_id);
API_EXPORT(int) ap_release_mutex(mutex *mutex_id);
API_EXPORT(void) ap_destroy_mutex(mutex *mutex_id);

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

#else /* ndef MULTITHREAD */

#define APACHE_TLS
/* Only define the ones actually used, for now */
extern void *ap_dummy_mutex;

#define ap_create_mutex(name)	((mutex *)ap_dummy_mutex)
#define ap_acquire_mutex(mutex_id)	((int)MULTI_OK)
#define ap_release_mutex(mutex_id)	((int)MULTI_OK)
#define ap_destroy_mutex(mutex_id)

#endif /* ndef MULTITHREAD */

#ifdef __cplusplus
}
#endif

#endif /* !APACHE_MULTITHREAD_H */
