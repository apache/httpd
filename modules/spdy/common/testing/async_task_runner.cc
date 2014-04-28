// Copyright 2012 Google Inc. All Rights Reserved.
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

#include "mod_spdy/common/testing/async_task_runner.h"

#include "base/basictypes.h"
#include "base/logging.h"
#include "mod_spdy/common/executor.h"
#include "mod_spdy/common/testing/notification.h"
#include "mod_spdy/common/thread_pool.h"
#include "net/instaweb/util/public/function.h"

namespace mod_spdy {

namespace testing {

namespace {

class TaskFunction : public net_instaweb::Function {
 public:
  TaskFunction(AsyncTaskRunner::Task* task, Notification* done)
      : task_(task), done_(done) {}
  virtual ~TaskFunction() {}
 protected:
  // net_instaweb::Function methods:
  virtual void Run() {
    task_->Run();
    done_->Set();
  }
  virtual void Cancel() {}
 private:
  AsyncTaskRunner::Task* const task_;
  Notification* const done_;
  DISALLOW_COPY_AND_ASSIGN(TaskFunction);
};

}  // namespace

AsyncTaskRunner::Task::Task() {}

AsyncTaskRunner::Task::~Task() {}

AsyncTaskRunner::AsyncTaskRunner(Task* task)
    : task_(task), thread_pool_(1, 1) {}

AsyncTaskRunner::~AsyncTaskRunner() {}

bool AsyncTaskRunner::Start() {
  // Make sure we haven't started yet.
  DCHECK(executor_ == NULL);

  if (!thread_pool_.Start()) {
    return false;
  }
  executor_.reset(thread_pool_.NewExecutor());
  executor_->AddTask(new TaskFunction(task_.get(), &notification_), 0);
  return true;
}

}  // namespace testing

}  // namespace mod_spdy
