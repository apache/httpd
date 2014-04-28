// Copyright 2011 Google Inc. All Rights Reserved.
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

#include <iostream>

#include "apr_general.h"

#include "base/basictypes.h"
#include "base/logging.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace {

// Class to ensure that APR gets initialized and torn down.
class AprInitializer {
 public:
  AprInitializer() {
    const apr_status_t status = apr_initialize();
    CHECK(status == APR_SUCCESS) << "APR initialization failed.";
  }
  ~AprInitializer() {
    apr_terminate();
  }
 private:
  DISALLOW_COPY_AND_ASSIGN(AprInitializer);
};

}  // namespace

int main(int argc, char **argv) {
  std::cout << "Running main() from spdy_apache_test_main.cc\n";
  testing::InitGoogleTest(&argc, argv);
  AprInitializer apr_initializer;
  return RUN_ALL_TESTS();
}
