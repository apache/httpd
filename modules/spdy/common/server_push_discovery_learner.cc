// Copyright 2013 Google Inc.
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

#include "mod_spdy/common/server_push_discovery_learner.h"

#include <algorithm>
#include <utility>

#include "base/strings/string_util.h"

namespace mod_spdy {

namespace {

int32_t GetPriorityFromExtension(const std::string& url) {
  if (EndsWith(url, ".js", false)) {
    return 1;
  } else if (EndsWith(url, ".css", false)) {
    return 1;
  } else {
    return -1;
  }
}

}  // namespace

ServerPushDiscoveryLearner::ServerPushDiscoveryLearner() {}

std::vector<ServerPushDiscoveryLearner::Push>
ServerPushDiscoveryLearner::GetPushes(const std::string& master_url) {
  base::AutoLock lock(lock_);
  UrlData& url_data = url_data_[master_url];
  std::vector<Push> pushes;

  uint64_t threshold = url_data.first_hit_count / 2;

  std::vector<AdjacentData> significant_adjacents;

  for (std::map<std::string, AdjacentData>::const_iterator it =
           url_data.adjacents.begin(); it != url_data.adjacents.end(); ++it) {
    if (it->second.hit_count >= threshold)
      significant_adjacents.push_back(it->second);
  }

  // Sort by average time from initial request. We want to provide the child
  // resources that the client needs immediately with a higher priority.
  std::sort(significant_adjacents.begin(), significant_adjacents.end(),
            &CompareAdjacentDataByAverageTimeFromInit);

  for (size_t i = 0; i < significant_adjacents.size(); ++i) {
    const AdjacentData& adjacent = significant_adjacents[i];

    // Give certain URLs fixed high priorities based on their extension.
    int32_t priority = GetPriorityFromExtension(adjacent.adjacent_url);

    // Otherwise, assign a higher priority based on its average request order.
    if (priority < 0) {
      priority = 2 + (i * 6 / significant_adjacents.size());
    }

    pushes.push_back(Push(adjacent.adjacent_url, priority));
  }

  return pushes;
}

void ServerPushDiscoveryLearner::AddFirstHit(const std::string& master_url) {
  base::AutoLock lock(lock_);
  UrlData& url_data = url_data_[master_url];
  ++url_data.first_hit_count;
}

void ServerPushDiscoveryLearner::AddAdjacentHit(const std::string& master_url,
                                                const std::string& adjacent_url,
                                                int64_t time_from_init) {
  base::AutoLock lock(lock_);
  std::map<std::string, AdjacentData>& master_url_adjacents =
      url_data_[master_url].adjacents;

  if (master_url_adjacents.find(adjacent_url) == master_url_adjacents.end()) {
    master_url_adjacents.insert(
        make_pair(adjacent_url, AdjacentData(adjacent_url)));
  }

  AdjacentData& adjacent_data = master_url_adjacents.find(adjacent_url)->second;

  ++adjacent_data.hit_count;
  double inverse_hit_count = 1.0 / adjacent_data.hit_count;

  adjacent_data.average_time_from_init =
      inverse_hit_count * time_from_init +
      (1 - inverse_hit_count) * adjacent_data.average_time_from_init;
}

// static
bool ServerPushDiscoveryLearner::CompareAdjacentDataByAverageTimeFromInit(
    const AdjacentData& a, const AdjacentData& b) {
  return a.average_time_from_init < b.average_time_from_init;
}

}  // namespace mod_spdy
