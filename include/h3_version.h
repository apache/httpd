/* Auto-generated - do not edit */
/*
 * Copyright (c) 2026 The mod_http3 Project Authors. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef H3_VERSION_H
#define H3_VERSION_H

#define MOD_HTTP3_VERSION_MAJOR 0
#define MOD_HTTP3_VERSION_MINOR 0
#define MOD_HTTP3_VERSION_PATCH 29

// Construct a 24-bit packed version number from major, minor and patch. Version 1.2.3 becomes 0x010203.
#define MOD_HTTP3_MAKE_VERSION(major, minor, patch) (((major) << 16) | ((minor) << 8) | (patch))

#define MOD_HTTP3_VERSION MOD_HTTP3_MAKE_VERSION(MOD_HTTP3_VERSION_MAJOR, MOD_HTTP3_VERSION_MINOR, MOD_HTTP3_VERSION_PATCH)

#define MOD_HTTP3_VERSION_STRING "0.0.29"

#endif /* H3_VERSION_H */
