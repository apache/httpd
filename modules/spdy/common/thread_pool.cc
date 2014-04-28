// Copyright 2012 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "mod_spdy/common/thread_pool.h"

#include <map>
#include <set>
#include <vector>

#include "base/basictypes.h"
#include "base/memory/scoped_ptr.h"
#include "base/synchronization/condition_variable.h"
#include "base/synchronization/lock.h"
#include "base/threading/platform_thread.h"
#include "base/time/time.h"
#include "mod_spdy/common/executor.h"
#include "net/instaweb/util/public/function.h"
#include "net/spdy/spdy_protocol.h"

namespace {

// Shut down a worker thread after it has been idle for this many seconds:
const int64 kDefaultMaxWorkerIdleSeconds = 60;

}  // namespace

namespace mod_spdy {

// An executor that uses the ThreadPool to execute tasks.  Returned by
// ThreadPool::NewExecutor.
class ThreadPool::ThreadPoolExecutor : public Executor {
 public:
  explicit ThreadPoolExecutor(ThreadPool* master)
      : master_(master),
        stopping_condvar_(&master_->lock_),
        stopped_(false) {}
  virtual ~ThreadPoolExecutor() { Stop(); }

  // Executor methods:
  virtual void AddTask(net_instaweb::Function* task,
                       net::SpdyPriority priority);
  virtual void Stop();

 private:
  friend class ThreadPool;
  ThreadPool* const master_;
  base::ConditionVariable stopping_condvar_;
  bool stopped_;  // protected by master_->lock_

  DISALLOW_COPY_AND_ASSIGN(ThreadPoolExecutor);
};

// Add a task to the executor; if the executor has already been stopped, just
// cancel the task immediately.
void ThreadPool::ThreadPoolExecutor::AddTask(net_instaweb::Function* task,
                                             net::SpdyPriority priority) {
  {
    base::AutoLock autolock(master_->lock_);

    // Clean up any zombie WorkerThreads in the ThreadPool that are waiting for
    // reaping.  If the OS process we're in accumulates too many unjoined
    // zombie threads over time, the OS might not be able to spawn a new thread
    // below.  So right now is a good time to clean them up.
    if (!master_->zombies_.empty()) {
      std::set<WorkerThread*> zombies;
      zombies.swap(master_->zombies_);
      // Joining these threads should be basically instant, since they've
      // already terminated.  But to be safe, let's unlock while we join them.
      base::AutoUnlock autounlock(master_->lock_);
      ThreadPool::JoinThreads(zombies);
    }

    // The thread pool shouldn't be shutting down until all executors are
    // destroyed.  Since this executor clearly still exists, the thread pool
    // must still be open.
    DCHECK(!master_->shutting_down_);

    // If the executor hasn't been stopped, add the task to the queue and
    // notify a worker that there's a new task ready to be taken.
    if (!stopped_) {
      master_->task_queue_.insert(std::make_pair(priority, Task(task, this)));
      master_->worker_condvar_.Signal();
      master_->StartNewWorkerIfNeeded();
      return;
    }
  }

  // If this executor has already been stopped, just cancel the task (after
  // releasing the lock).
  task->CallCancel();
}

// Stop the executor.  Cancel all pending tasks in the thread pool owned by
// this executor, and then block until all active tasks owned by this executor
// complete.  Stopping the executor more than once has no effect.
void ThreadPool::ThreadPoolExecutor::Stop() {
  std::vector<net_instaweb::Function*> functions_to_cancel;
  {
    base::AutoLock autolock(master_->lock_);
    if (stopped_) {
      return;
    }
    stopped_ = true;

    // Remove all tasks owned by this executor from the queue, and collect up
    // the function objects to be cancelled.
    TaskQueue::iterator next_iter = master_->task_queue_.begin();
    while (next_iter != master_->task_queue_.end()) {
      TaskQueue::iterator iter = next_iter;
      const Task& task = iter->second;
      ++next_iter;  // Increment next_iter _before_ we might erase iter.
      if (task.owner == this) {
        functions_to_cancel.push_back(task.function);
        master_->task_queue_.erase(iter);
      }
    }
  }

  // Unlock while we cancel the functions, so we're not hogging the lock for
  // too long, and to avoid potential deadlock if the cancel method tries to do
  // anything with the thread pool.
  for (std::vector<net_instaweb::Function*>::const_iterator iter =
           functions_to_cancel.begin();
       iter != functions_to_cancel.end(); ++iter) {
    (*iter)->CallCancel();
  }
  // CallCancel deletes the Function objects, invalidating the pointers in this
  // list, so let's go ahead and clear it (which also saves a little memory
  // while we're blocked below).
  functions_to_cancel.clear();

  // Block until all our active tasks are completed.
  {
    base::AutoLock autolock(master_->lock_);
    while (master_->active_task_counts_.count(this) > 0) {
      stopping_condvar_.Wait();
    }
  }
}

// A WorkerThread object wraps a platform-specific thread handle, and provides
// the method run by that thread (ThreadMain).
class ThreadPool::WorkerThread : public base::PlatformThread::Delegate {
 public:
  explicit WorkerThread(ThreadPool* master);
  virtual ~WorkerThread();

  // Start the thread running.  Return false on failure.  If this succeeds,
  // then you must call Join() before deleting this object.
  bool Start();

  // Block until the thread completes.  You must set master_->shutting_down_ to
  // true before calling this method, or the thread will never terminate.
  // You shouldn't be holding master_->lock_ when calling this.
  void Join();

  // base::PlatformThread::Delegate method:
  virtual void ThreadMain();

 private:
  enum ThreadState { NOT_STARTED, STARTED, JOINED };

  ThreadPool* const master_;
  // If two master threads are sharing the same ThreadPool, then Start() and
  // Join() might get called by different threads.  So to be safe we use a lock
  // to protect the two below fields.
  base::Lock thread_lock_;
  ThreadState state_;
  base::PlatformThreadHandle thread_id_;

  DISALLOW_COPY_AND_ASSIGN(WorkerThread);
};

ThreadPool::WorkerThread::WorkerThread(ThreadPool* master)
    : master_(master), state_(NOT_STARTED), thread_id_() {}

ThreadPool::WorkerThread::~WorkerThread() {
  base::AutoLock autolock(thread_lock_);
  // If we started the thread, we _must_ join it before deleting this object,
  // or else the thread won't get cleaned up by the OS.
  DCHECK(state_ == NOT_STARTED || state_ == JOINED);
}

bool ThreadPool::WorkerThread::Start() {
  base::AutoLock autolock(thread_lock_);
  DCHECK_EQ(NOT_STARTED, state_);
  if (base::PlatformThread::Create(0, this, &thread_id_)) {
    state_ = STARTED;
    return true;
  }
  return false;
}

void ThreadPool::WorkerThread::Join() {
  base::AutoLock autolock(thread_lock_);
  DCHECK_EQ(STARTED, state_);
  base::PlatformThread::Join(thread_id_);
  state_ = JOINED;
}

// This is the code executed by the thread; when this method returns, the
// thread will terminate.
void ThreadPool::WorkerThread::ThreadMain() {
  // We start by grabbing the master lock, but we release it below whenever we
  // are 1) waiting for a new task or 2) executing a task.  So in fact most of
  // the time we are not holding the lock.
  base::AutoLock autolock(master_->lock_);
  while (true) {
    // Wait until there's a task available (or we're shutting down), but don't
    // stay idle for more than kMaxWorkerIdleSeconds seconds.
    base::TimeDelta time_remaining = master_->max_thread_idle_time_;
    while (!master_->shutting_down_ && master_->task_queue_.empty() &&
           time_remaining.InSecondsF() > 0.0) {
      // Note that TimedWait can wake up spuriously before the time runs out,
      // so we need to measure how long we actually waited for.
      const base::Time start = base::Time::Now();
      master_->worker_condvar_.TimedWait(time_remaining);
      const base::Time end = base::Time::Now();
      // Note that the system clock can go backwards if it is reset, so make
      // sure we never _increase_ time_remaining.
      if (end > start) {
        time_remaining -= end - start;
      }
    }

    // If the thread pool is shutting down, terminate this thread; the master
    // is about to join/delete us (in its destructor).
    if (master_->shutting_down_) {
      return;
    }

    // If we ran out of time without getting a task, maybe this thread should
    // shut itself down.
    if (master_->task_queue_.empty()) {
      DCHECK_LE(time_remaining.InSecondsF(), 0.0);
      // Ask the master if we should stop.  If this returns true, this worker
      // has been zombified, so we're free to terminate the thread.
      if (master_->TryZombifyIdleThread(this)) {
        return;  // Yes, we should stop; terminate the thread.
      } else {
        continue;  // No, we shouldn't stop; jump to the top of the while loop.
      }
    }

    // Otherwise, there must be at least one task available now.  Grab one from
    // the master, who will then treat us as busy until we complete it.
    const Task task = master_->GetNextTask();
    // Release the lock while we execute the task.  Note that we use AutoUnlock
    // here rather than one AutoLock for the above code and another for the
    // below code, so that we don't have to release and reacquire the lock at
    // the edge of the while-loop.
    {
      base::AutoUnlock autounlock(master_->lock_);
      task.function->CallRun();
    }
    // Inform the master we have completed the task and are no longer busy.
    master_->OnTaskComplete(task);
  }
}

ThreadPool::ThreadPool(int min_threads, int max_threads)
    : min_threads_(min_threads),
      max_threads_(max_threads),
      max_thread_idle_time_(
          base::TimeDelta::FromSeconds(kDefaultMaxWorkerIdleSeconds)),
      worker_condvar_(&lock_),
      num_busy_workers_(0),
      shutting_down_(false) {
  DCHECK_GE(max_thread_idle_time_.InSecondsF(), 0.0);
  // Note that we check e.g. min_threads rather than min_threads_ (which is
  // unsigned), in order to catch negative numbers.
  DCHECK_GE(min_threads, 1);
  DCHECK_GE(max_threads, 1);
  DCHECK_LE(min_threads_, max_threads_);
}

ThreadPool::ThreadPool(int min_threads, int max_threads,
                       base::TimeDelta max_thread_idle_time)
    : min_threads_(min_threads),
      max_threads_(max_threads),
      max_thread_idle_time_(max_thread_idle_time),
      worker_condvar_(&lock_),
      num_busy_workers_(0),
      shutting_down_(false) {
  DCHECK_GE(max_thread_idle_time_.InSecondsF(), 0.0);
  DCHECK_GE(min_threads, 1);
  DCHECK_GE(max_threads, 1);
  DCHECK_LE(min_threads_, max_threads_);
}

ThreadPool::~ThreadPool() {
  base::AutoLock autolock(lock_);

  // If we're doing things right, all the Executors should have been
  // destroyed before the ThreadPool is destroyed, so there should be no
  // pending or active tasks.
  DCHECK(task_queue_.empty());
  DCHECK(active_task_counts_.empty());

  // Wake up all the worker threads and tell them to shut down.
  shutting_down_ = true;
  worker_condvar_.Broadcast();

  // Clean up all our threads.
  std::set<WorkerThread*> threads;
  zombies_.swap(threads);
  threads.insert(workers_.begin(), workers_.end());
  workers_.clear();
  {
    base::AutoUnlock autounlock(lock_);
    JoinThreads(threads);
  }

  // Because we had shutting_down_ set to true, nothing should have been added
  // to our WorkerThread sets while we were unlocked.  So we should be all
  // cleaned up now.
  DCHECK(workers_.empty());
  DCHECK(zombies_.empty());
  DCHECK(task_queue_.empty());
  DCHECK(active_task_counts_.empty());
}

bool ThreadPool::Start() {
  base::AutoLock autolock(lock_);
  DCHECK(task_queue_.empty());
  DCHECK(workers_.empty());
  // Start up min_threads_ workers; if any of the worker threads fail to start,
  // then this method fails and the ThreadPool should be deleted.
  for (unsigned int i = 0; i < min_threads_; ++i) {
    scoped_ptr<WorkerThread> worker(new WorkerThread(this));
    if (!worker->Start()) {
      return false;
    }
    workers_.insert(worker.release());
  }
  DCHECK_EQ(min_threads_, workers_.size());
  return true;
}

Executor* ThreadPool::NewExecutor() {
  return new ThreadPoolExecutor(this);
}

int ThreadPool::GetNumWorkersForTest() {
  base::AutoLock autolock(lock_);
  return workers_.size();
}

int ThreadPool::GetNumIdleWorkersForTest() {
  base::AutoLock autolock(lock_);
  DCHECK_GE(num_busy_workers_, 0u);
  DCHECK_LE(num_busy_workers_, workers_.size());
  return workers_.size() - num_busy_workers_;
}

int ThreadPool::GetNumZombiesForTest() {
  base::AutoLock autolock(lock_);
  return zombies_.size();
}

// This method is called each time we add a new task to the thread pool.
void ThreadPool::StartNewWorkerIfNeeded() {
  lock_.AssertAcquired();
  DCHECK_GE(num_busy_workers_, 0u);
  DCHECK_LE(num_busy_workers_, workers_.size());
  DCHECK_GE(workers_.size(), min_threads_);
  DCHECK_LE(workers_.size(), max_threads_);

  // We create a new worker to handle the task _unless_ either 1) we're already
  // at the maximum number of threads, or 2) there are already enough idle
  // workers sitting around to take on this task (and all other pending tasks
  // that the idle workers haven't yet had a chance to pick up).
  if (workers_.size() >= max_threads_ ||
      task_queue_.size() <= workers_.size() - num_busy_workers_) {
    return;
  }

  scoped_ptr<WorkerThread> worker(new WorkerThread(this));
  if (worker->Start()) {
    workers_.insert(worker.release());
  } else {
    LOG(ERROR) << "Failed to start new worker thread.";
  }
}

// static
void ThreadPool::JoinThreads(const std::set<WorkerThread*>& threads) {
  for (std::set<WorkerThread*>::const_iterator iter = threads.begin();
       iter != threads.end(); ++iter) {
    WorkerThread* thread = *iter;
    thread->Join();
    delete thread;
  }
}

// Call when the worker thread has been idle for a while.  Either return false
// (worker should continue waiting for tasks), or zombify the worker and return
// true (worker thread should immediately terminate).
bool ThreadPool::TryZombifyIdleThread(WorkerThread* thread) {
  lock_.AssertAcquired();

  // Don't terminate the thread if the thread pool is already at the minimum
  // number of threads.
  DCHECK_GE(workers_.size(), min_threads_);
  if (workers_.size() <= min_threads_) {
    return false;
  }

  // Remove this thread from the worker set.
  DCHECK_EQ(1u, workers_.count(thread));
  workers_.erase(thread);

  // When a (joinable) thread terminates, it must still be cleaned up, either
  // by another thread joining it, or by detatching it.  However, the thread
  // pool's not shutting down here, so the master thread doesn't know to join
  // this thread that we're in now, and the Chromium thread abstraction we're
  // using doesn't currently allow us to detach a thread.  So instead, we place
  // this WorkerThread object into a "zombie" set, which the master thread can
  // reap later on.  Threads that have terminated but that haven't been joined
  // yet use up only a small amount of memory (I think), so it's okay if we
  // don't reap it right away, as long as we don't try to spawn new threads
  // while there's still lots of zombies.
  DCHECK(!shutting_down_);
  DCHECK_EQ(0u, zombies_.count(thread));
  zombies_.insert(thread);
  return true;
}

// Get and return the next task from the queue (which must be non-empty), and
// update our various counters to indicate that the calling worker is busy
// executing this task.
ThreadPool::Task ThreadPool::GetNextTask() {
  lock_.AssertAcquired();

  // Pop the highest-priority task from the queue.  Note that smaller values
  // correspond to higher priorities (SPDY draft 3 section 2.3.3), so
  // task_queue_.begin() gets us the highest-priority pending task.
  DCHECK(!task_queue_.empty());
  TaskQueue::iterator task_iter = task_queue_.begin();
  const Task task = task_iter->second;
  task_queue_.erase(task_iter);

  // Increment the count of active tasks for the executor that owns this
  // task; we'll decrement it again when the task completes.
  ++(active_task_counts_[task.owner]);

  // The worker that takes this task will be busy until it completes it.
  DCHECK_LT(num_busy_workers_, workers_.size());
  ++num_busy_workers_;

  return task;
}

// Call to indicate that the task has been completed; update our various
// counters to indicate that the calling worker is no longer busy executing
// this task.
void ThreadPool::OnTaskComplete(Task task) {
  lock_.AssertAcquired();

  // The worker that just finished this task is no longer busy.
  DCHECK_GE(num_busy_workers_, 1u);
  --num_busy_workers_;

  // We've completed the task and reaquired the lock, so decrement the count
  // of active tasks for this owner.
  OwnerMap::iterator count_iter = active_task_counts_.find(task.owner);
  DCHECK(count_iter != active_task_counts_.end());
  DCHECK(count_iter->second > 0);
  --(count_iter->second);

  // If this was the last active task for the owner, notify anyone who might be
  // waiting for the owner to stop.
  if (count_iter->second == 0) {
    active_task_counts_.erase(count_iter);
    task.owner->stopping_condvar_.Broadcast();
  }
}

}  // namespace mod_spdy
