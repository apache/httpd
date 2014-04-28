# Copyright 2010 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# mod_spdy common gyp configuration.
{
  'variables': {
    'library%': 'static_library',

    # Don't use the gold linker:
    'linux_use_gold_binary': 0,
    'linux_use_gold_flags': 0,

    # Don't use the system Apache dev files by default:
    'use_system_apache_dev%': 0,

    # Turn these off to prevent Chromium's build config from bothering us about
    # things we don't care about for mod_spdy:
    'clang_use_chrome_plugins': 0,
    'incremental_chrome_dll': 0,
    'use_official_google_api_keys': 0,
  },

  # Import Chromium's common.gypi to inherit their build configuration.
  'includes': [
    '../third_party/chromium/src/build/common.gypi',
  ],

  # Modify the Chromium configuration as needed:
  'target_defaults': {
    # Make sure our shadow view of chromium source is available to
    # targets that don't explicitly declare their dependencies and
    # assume chromium source headers are available from the root
    # (third_party/modp_b64 is one such target).
    'include_dirs': [
      '<(DEPTH)/third_party/chromium/src',
    ],
  },
}
