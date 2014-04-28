/* Copyright 2012 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
// Contains IdPool, a class for managing 16-bit process-global IDs.

#include "mod_spdy/apache/id_pool.h"

#include <vector>
#include <set>

#include "base/basictypes.h"
#include "base/logging.h"

namespace mod_spdy {

IdPool* IdPool::g_instance = NULL;
const uint16 IdPool::kOverFlowId;

IdPool::IdPool()
    : next_never_used_(0) /* So it gets incremented to 1 in ::Alloc */ {
}

IdPool::~IdPool() {
}

void IdPool::CreateInstance() {
  DCHECK(g_instance == NULL);
  g_instance = new IdPool();
}

void IdPool::DestroyInstance() {
  DCHECK(g_instance != NULL);
  delete g_instance;
  g_instance = NULL;
}

uint16 IdPool::Alloc() {
  base::AutoLock lock(mutex_);
  if (!free_list_.empty()) {
    uint16 id = free_list_.back();
    free_list_.pop_back();
    alloc_set_.insert(id);
    return id;
  }

  // We do not use 0 or kOverFlowId normally..
  if (alloc_set_.size() == (0x10000 - 2)) {
    LOG(WARNING) << "Out of slave fetch IDs, things may break";
    return kOverFlowId;
  }

  // Freelist is empty, but we haven't yet used some ID, so return it.
  ++next_never_used_;
  DCHECK(next_never_used_ != kOverFlowId);
  DCHECK(alloc_set_.find(next_never_used_) == alloc_set_.end());
  alloc_set_.insert(next_never_used_);
  return next_never_used_;
}

void IdPool::Free(uint16 id) {
  if (id == kOverFlowId) {
    return;
  }

  base::AutoLock lock(mutex_);
  DCHECK(alloc_set_.find(id) != alloc_set_.end());
  alloc_set_.erase(id);
  free_list_.push_back(id);
}

}  // namespace mod_spdy
