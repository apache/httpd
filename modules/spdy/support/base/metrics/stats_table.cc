// Copyright (c) 2006-2008 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// A stubbed version of stats_table.cc that doesn't do anything. These
// functions must be defined in order to link with code that updates
// stats (such as spdy_framer.cc).

#include "base/metrics/stats_table.h"

namespace base {

StatsTable* StatsTable::current() { return NULL; }

int StatsTable::RegisterThread(const std::string& name) {
  return 0;
}

int StatsTable::GetSlot() const {
  return 0;
}

int StatsTable::FindCounter(const std::string& name) {
  return 0;
}

int* StatsTable::GetLocation(int counter_id, int slot_id) const {
  return NULL;
}

}  // namespace base
