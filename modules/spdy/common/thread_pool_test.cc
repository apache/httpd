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

#include <vector>

#include "base/basictypes.h"
#include "base/memory/scoped_ptr.h"
#include "base/synchronization/condition_variable.h"
#include "base/synchronization/lock.h"
#include "base/threading/platform_thread.h"
#include "base/time/time.h"
#include "mod_spdy/common/executor.h"
#include "mod_spdy/common/testing/notification.h"
#include "net/instaweb/util/public/function.h"
#include "net/spdy/spdy_protocol.h"
#include "testing/gtest/include/gtest/gtest.h"

// When adding tests here, try to keep them robust against thread scheduling
// differences from run to run.  In particular, they shouldn't fail just
// because you're running under Valgrind.

namespace {

// When run, a TestFunction waits for `wait` millis, then sets `*result` to
// RAN.  When cancelled, it sets *result to CANCELLED.
class TestFunction : public net_instaweb::Function {
 public:
  enum Result { NOTHING, RAN, CANCELLED };
  TestFunction(int wait, base::Lock* lock, Result* result)
      : wait_(wait), lock_(lock), result_(result) {}
  virtual ~TestFunction() {}
 protected:
  // net_instaweb::Function methods:
  virtual void Run() {
    base::PlatformThread::Sleep(base::TimeDelta::FromMilliseconds(wait_));
    base::AutoLock autolock(*lock_);
    *result_ = RAN;
  }
  virtual void Cancel() {
    base::AutoLock autolock(*lock_);
    *result_ = CANCELLED;
  }
 private:
  const int wait_;
  base::Lock* const lock_;
  Result* const result_;
  DISALLOW_COPY_AND_ASSIGN(TestFunction);
};

// Test that we execute tasks concurrently, that that we respect priorities
// when pulling tasks from the queue.
TEST(ThreadPoolTest, ConcurrencyAndPrioritization) {
  // Create a thread pool with 2 threads, and an executor.
  mod_spdy::ThreadPool thread_pool(2, 2);
  ASSERT_TRUE(thread_pool.Start());
  scoped_ptr<mod_spdy::Executor> executor(thread_pool.NewExecutor());

  base::Lock lock;
  TestFunction::Result result0 = TestFunction::NOTHING;
  TestFunction::Result result1 = TestFunction::NOTHING;
  TestFunction::Result result2 = TestFunction::NOTHING;
  TestFunction::Result result3 = TestFunction::NOTHING;

  // Create a high-priority TestFunction, which waits for 200 millis then
  // records that it ran.
  executor->AddTask(new TestFunction(200, &lock, &result0), 0);
  // Create several TestFunctions at different priorities.  Each waits 100
  // millis then records that it ran.
  executor->AddTask(new TestFunction(100, &lock, &result1), 1);
  executor->AddTask(new TestFunction(100, &lock, &result3), 3);
  executor->AddTask(new TestFunction(100, &lock, &result2), 2);

  // Wait 150 millis, then stop the executor.
  base::PlatformThread::Sleep(base::TimeDelta::FromMilliseconds(150));
  executor->Stop();

  // Only TestFunctions that _started_ within the first 150 millis should have
  // run; the others should have been cancelled.
  //   - The priority-0 function should have started first, on the first
  //     thread.  It finishes after 200 millis.
  //   - The priority-1 function should run on the second thread.  It finishes
  //     after 100 millis.
  //   - The priority-2 function should run on the second thread after the
  //     priority-1 function finishes, even though it was pushed last, because
  //     it's higher-priority than the priority-3 function.  It finishes at the
  //     200-milli mark.
  //   - The priority-3 function should not get a chance to run, because we
  //     stop the executor after 150 millis, and the soonest it could start is
  //     the 200-milli mark.
  base::AutoLock autolock(lock);
  EXPECT_EQ(TestFunction::RAN, result0);
  EXPECT_EQ(TestFunction::RAN, result1);
  EXPECT_EQ(TestFunction::RAN, result2);
  EXPECT_EQ(TestFunction::CANCELLED, result3);
}

// Test that stopping one executor doesn't affect tasks on another executor
// from the same ThreadPool.
TEST(ThreadPoolTest, MultipleExecutors) {
  // Create a thread pool with 3 threads, and two executors.
  mod_spdy::ThreadPool thread_pool(3, 3);
  ASSERT_TRUE(thread_pool.Start());
  scoped_ptr<mod_spdy::Executor> executor1(thread_pool.NewExecutor());
  scoped_ptr<mod_spdy::Executor> executor2(thread_pool.NewExecutor());

  base::Lock lock;
  TestFunction::Result e1r1 = TestFunction::NOTHING;
  TestFunction::Result e1r2 = TestFunction::NOTHING;
  TestFunction::Result e1r3 = TestFunction::NOTHING;
  TestFunction::Result e2r1 = TestFunction::NOTHING;
  TestFunction::Result e2r2 = TestFunction::NOTHING;
  TestFunction::Result e2r3 = TestFunction::NOTHING;

  // Add some tasks to the executors.  Each one takes 50 millis to run.
  executor1->AddTask(new TestFunction(50, &lock, &e1r1), 0);
  executor2->AddTask(new TestFunction(50, &lock, &e2r1), 0);
  executor1->AddTask(new TestFunction(50, &lock, &e1r2), 0);
  executor2->AddTask(new TestFunction(50, &lock, &e2r2), 1);
  executor1->AddTask(new TestFunction(50, &lock, &e1r3), 3);
  executor2->AddTask(new TestFunction(50, &lock, &e2r3), 1);

  // Wait 20 millis (to make sure the first few tasks got picked up), then
  // destroy executor2, which should stop it.  Finally, sleep another 100
  // millis to give the remaining tasks a chance to finish.
  base::PlatformThread::Sleep(base::TimeDelta::FromMilliseconds(20));
  executor2.reset();
  base::PlatformThread::Sleep(base::TimeDelta::FromMilliseconds(100));

  // The three high priority tasks should have all run.  The other two tasks on
  // executor2 should have been cancelled when we stopped executor2, but the
  // low-priority task on executor1 should have been left untouched, and
  // allowed to finish.
  base::AutoLock autolock(lock);
  EXPECT_EQ(TestFunction::RAN, e1r1);
  EXPECT_EQ(TestFunction::RAN, e2r1);
  EXPECT_EQ(TestFunction::RAN, e1r2);
  EXPECT_EQ(TestFunction::CANCELLED, e2r2);
  EXPECT_EQ(TestFunction::RAN, e1r3);
  EXPECT_EQ(TestFunction::CANCELLED, e2r3);
}

// When run, a WaitFunction blocks until the notification is set.
class WaitFunction : public net_instaweb::Function {
 public:
  WaitFunction(mod_spdy::testing::Notification* notification)
      : notification_(notification) {}
  virtual ~WaitFunction() {}
 protected:
  // net_instaweb::Function methods:
  virtual void Run() {
    notification_->Wait();
  }
  virtual void Cancel() {}
 private:
  mod_spdy::testing::Notification* const notification_;
  DISALLOW_COPY_AND_ASSIGN(WaitFunction);
};

// When run, an IdFunction pushes its ID onto the vector.
class IdFunction : public net_instaweb::Function {
 public:
  IdFunction(int id, base::Lock* lock, base::ConditionVariable* condvar,
             std::vector<int>* output)
      : id_(id), lock_(lock), condvar_(condvar), output_(output) {}
  virtual ~IdFunction() {}
 protected:
  // net_instaweb::Function methods:
  virtual void Run() {
    base::AutoLock autolock(*lock_);
    output_->push_back(id_);
    condvar_->Broadcast();
  }
  virtual void Cancel() {}
 private:
  const int id_;
  base::Lock* const lock_;
  base::ConditionVariable* const condvar_;
  std::vector<int>* const output_;
  DISALLOW_COPY_AND_ASSIGN(IdFunction);
};

// Test that if many tasks of the same priority are added, they are run in the
// order they were added.
TEST(ThreadPoolTest, SamePriorityTasksAreFIFO) {
  // Create a thread pool with just one thread, and an executor.
  mod_spdy::ThreadPool thread_pool(1, 1);
  ASSERT_TRUE(thread_pool.Start());
  scoped_ptr<mod_spdy::Executor> executor(thread_pool.NewExecutor());

  // First, make sure no other tasks will get started until we set the
  // notification.
  mod_spdy::testing::Notification start;
  executor->AddTask(new WaitFunction(&start), 0);

  // Add many tasks to the executor, of varying priorities.
  const int num_tasks_each_priority = 1000;
  const int total_num_tasks = 3 * num_tasks_each_priority;
  base::Lock lock;
  base::ConditionVariable condvar(&lock);
  std::vector<int> ids;  // protected by lock
  for (int id = 0; id < num_tasks_each_priority; ++id) {
    executor->AddTask(new IdFunction(id, &lock, &condvar, &ids), 1);
    executor->AddTask(new IdFunction(id + num_tasks_each_priority,
                                     &lock, &condvar, &ids), 2);
    executor->AddTask(new IdFunction(id + 2 * num_tasks_each_priority,
                                     &lock, &condvar, &ids), 3);
  }

  // Start us off, then wait for all tasks to finish.
  start.Set();
  base::AutoLock autolock(lock);
  while (static_cast<int>(ids.size()) < total_num_tasks) {
    condvar.Wait();
  }

  // Check that the tasks were executed in order by the one worker thread.
  for (int index = 0; index < total_num_tasks; ++index) {
    ASSERT_EQ(index, ids[index])
        << "Task " << ids[index] << " finished in position " << index;
  }
}

// Add a test failure if the thread pool does not stabilize to the expected
// total/idle number of worker threads withing the given timeout.
void ExpectWorkersWithinTimeout(int expected_num_workers,
                                int expected_num_idle_workers,
                                mod_spdy::ThreadPool* thread_pool,
                                int timeout_millis) {
  int millis_remaining = timeout_millis;
  while (true) {
    const int actual_num_workers = thread_pool->GetNumWorkersForTest();
    const int actual_num_idle_workers =
        thread_pool->GetNumIdleWorkersForTest();
    if (actual_num_workers == expected_num_workers &&
        actual_num_idle_workers == expected_num_idle_workers) {
      return;
    }
    if (millis_remaining <= 0) {
      ADD_FAILURE() << "Timed out; expected " << expected_num_workers
                    << " worker(s) with " << expected_num_idle_workers
                    <<" idle; still at " << actual_num_workers
                    << " worker(s) with " << actual_num_idle_workers
                    << " idle after " << timeout_millis << "ms";
      return;
    }
    base::PlatformThread::Sleep(base::TimeDelta::FromMilliseconds(10));
    millis_remaining -= 10;
  }
}

// Test that we spawn new threads as needed, and allow them to die off after
// being idle for a while.
TEST(ThreadPoolTest, CreateAndRetireWorkers) {
  // Create a thread pool with min_threads < max_threads, and give it a short
  // max_thread_idle_time.
  const int idle_time_millis = 100;
  mod_spdy::ThreadPool thread_pool(
      2, 4, base::TimeDelta::FromMilliseconds(idle_time_millis));
  ASSERT_TRUE(thread_pool.Start());
  // As soon as we start the thread pool, there should be the minimum number of
  // workers (two), both counted as idle.
  EXPECT_EQ(2, thread_pool.GetNumWorkersForTest());
  EXPECT_EQ(2, thread_pool.GetNumIdleWorkersForTest());

  scoped_ptr<mod_spdy::Executor> executor(thread_pool.NewExecutor());

  // Start up three tasks.  That should push us up to three workers
  // immediately.  If we make sure to give those threads a chance to run, they
  // should soon pick up the tasks and all be busy.
  mod_spdy::testing::Notification done1;
  executor->AddTask(new WaitFunction(&done1), 0);
  executor->AddTask(new WaitFunction(&done1), 1);
  executor->AddTask(new WaitFunction(&done1), 2);
  EXPECT_EQ(3, thread_pool.GetNumWorkersForTest());
  ExpectWorkersWithinTimeout(3, 0, &thread_pool, 100);

  // Add three more tasks.  We should now be at the maximum number of workers,
  // and that fourth worker should be busy soon.
  mod_spdy::testing::Notification done2;
  executor->AddTask(new WaitFunction(&done2), 1);
  executor->AddTask(new WaitFunction(&done2), 2);
  executor->AddTask(new WaitFunction(&done2), 3);
  EXPECT_EQ(4, thread_pool.GetNumWorkersForTest());
  ExpectWorkersWithinTimeout(4, 0, &thread_pool, 100);

  // Allow the first group of tasks to finish.  There are now only three tasks
  // running, so one of our four threads should go idle.  If we wait for a
  // while after that, that thread should terminate and enter zombie mode.
  done1.Set();
  ExpectWorkersWithinTimeout(4, 1, &thread_pool, idle_time_millis / 2);
  ExpectWorkersWithinTimeout(3, 0, &thread_pool, 2 * idle_time_millis);
  EXPECT_EQ(1, thread_pool.GetNumZombiesForTest());

  // Allow the second group of tasks to finish.  There are no tasks left, so
  // all three threads should go idle.  If we wait for a while after that,
  // exactly one of the three should shut down, bringing us back down to the
  // minimum number of threads.  We should now have two zombie threads.
  done2.Set();
  ExpectWorkersWithinTimeout(3, 3, &thread_pool, idle_time_millis / 2);
  ExpectWorkersWithinTimeout(2, 2, &thread_pool, 2 * idle_time_millis);
  EXPECT_EQ(2, thread_pool.GetNumZombiesForTest());

  // Start some new new tasks.  This should cause us to immediately reap the
  // zombie threads, and soon, we should have three busy threads.
  mod_spdy::testing::Notification done3;
  executor->AddTask(new WaitFunction(&done3), 0);
  executor->AddTask(new WaitFunction(&done3), 2);
  executor->AddTask(new WaitFunction(&done3), 1);
  EXPECT_EQ(0, thread_pool.GetNumZombiesForTest());
  EXPECT_EQ(3, thread_pool.GetNumWorkersForTest());
  ExpectWorkersWithinTimeout(3, 0, &thread_pool, 100);

  // Let those tasks finish.  Once again, the threads should go idle, and then
  // one of them should terminate and enter zombie mode.
  done3.Set();
  ExpectWorkersWithinTimeout(3, 3, &thread_pool, idle_time_millis / 2);
  ExpectWorkersWithinTimeout(2, 2, &thread_pool, 2 * idle_time_millis);
  EXPECT_EQ(1, thread_pool.GetNumZombiesForTest());

  // When we exit the test, the thread pool's destructor should reap the zombie
  // thread (as well as shutting down the still-running workers).  We can
  // verify this by running this test under valgrind and making sure that no
  // memory is leaked.
}

}  // namespace
