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

{
  'variables': {
    # Turning on chromium_code mode enables extra compiler warnings.  See
    # src/build/common.gypi.
    'chromium_code': 1,
  },
  'targets': [
    {
      'target_name': 'spdy_common',
      'type': '<(library)',
      'dependencies': [
        '<(DEPTH)/base/base.gyp:base',
        '<(DEPTH)/build/build_util.gyp:mod_spdy_version_header',
        '<(DEPTH)/net/net.gyp:instaweb_util',
        '<(DEPTH)/net/net.gyp:spdy',
      ],
      'include_dirs': [
        '<(DEPTH)',
      ],
      'export_dependent_settings': [
        '<(DEPTH)/base/base.gyp:base',
        '<(DEPTH)/net/net.gyp:spdy',
      ],
      'sources': [
        'common/executor.cc',
        'common/http_request_visitor_interface.cc',
        'common/http_response_parser.cc',
        'common/http_response_visitor_interface.cc',
        'common/http_string_builder.cc',
        'common/http_to_spdy_converter.cc',
        'common/protocol_util.cc',
        'common/server_push_discovery_learner.cc',
        'common/server_push_discovery_session.cc',
        'common/shared_flow_control_window.cc',
        'common/spdy_frame_priority_queue.cc',
        'common/spdy_frame_queue.cc',
        'common/spdy_server_config.cc',
        'common/spdy_server_push_interface.cc',
        'common/spdy_session.cc',
        'common/spdy_session_io.cc',
        'common/spdy_stream.cc',
        'common/spdy_stream_task_factory.cc',
        'common/spdy_to_http_converter.cc',
        'common/thread_pool.cc',
      ],
    },
    {
      'target_name': 'spdy_apache',
      'type': '<(library)',
      'dependencies': [
        'spdy_common',
        '<(DEPTH)/base/base.gyp:base',
        '<(DEPTH)/build/build_util.gyp:mod_spdy_version_header',
        '<(DEPTH)/third_party/apache/httpd/httpd.gyp:include',
      ],
      'include_dirs': [
        '<(DEPTH)',
      ],
      'export_dependent_settings': [
        'spdy_common',
        '<(DEPTH)/base/base.gyp:base',
        '<(DEPTH)/third_party/apache/httpd/httpd.gyp:include',
      ],
      'sources': [
        'apache/apache_spdy_session_io.cc',
        'apache/apache_spdy_stream_task_factory.cc',
        'apache/config_commands.cc',
        'apache/config_util.cc',
        'apache/filters/http_to_spdy_filter.cc',
        'apache/filters/server_push_filter.cc',
        'apache/filters/spdy_to_http_filter.cc',
        'apache/id_pool.cc',
        'apache/log_message_handler.cc',
        'apache/master_connection_context.cc',
        'apache/pool_util.cc',
        'apache/sockaddr_util.cc',
        'apache/slave_connection.cc',
        'apache/slave_connection_api.cc',
        'apache/slave_connection_context.cc',
        'apache/ssl_util.cc',
      ],
    },
    {
      'target_name': 'mod_spdy',
      'type': 'loadable_module',
      'dependencies': [
        'spdy_apache',
        '<(DEPTH)/base/base.gyp:base',
        '<(DEPTH)/build/build_util.gyp:mod_spdy_version_header',
        '<(DEPTH)/net/net.gyp:spdy',
        '<(DEPTH)/third_party/apache/httpd/httpd.gyp:include',
      ],
      'include_dirs': [
        '<(DEPTH)',
      ],
      'sources': [
        'mod_spdy.cc',
      ],
      'conditions': [['OS == "mac"', {
        'xcode_settings': {
          # We must null out these two variables when building this target,
          # because it is a loadable_module (-bundle).
          'DYLIB_COMPATIBILITY_VERSION':'',
          'DYLIB_CURRENT_VERSION':'',
        }
      }]],
    },
    {
      'target_name': 'spdy_common_testing',
      'type': '<(library)',
      'dependencies': [
        '<(DEPTH)/base/base.gyp:base',
        '<(DEPTH)/net/net.gyp:instaweb_util',
        '<(DEPTH)/net/net.gyp:spdy',
        '<(DEPTH)/testing/gmock.gyp:gmock',
      ],
      'include_dirs': [
        '<(DEPTH)',
      ],
      'export_dependent_settings': [
        '<(DEPTH)/base/base.gyp:base',
        '<(DEPTH)/net/net.gyp:spdy',
        '<(DEPTH)/testing/gmock.gyp:gmock',
      ],
      'sources': [
        'common/testing/async_task_runner.cc',
        'common/testing/notification.cc',
        'common/testing/spdy_frame_matchers.cc',
      ],
    },
    {
      'target_name': 'spdy_common_test',
      'type': 'executable',
      'dependencies': [
        'spdy_common',
        'spdy_common_testing',
        '<(DEPTH)/testing/gmock.gyp:gmock',
        '<(DEPTH)/testing/gtest.gyp:gtest',
        '<(DEPTH)/testing/gtest.gyp:gtest_main',
      ],
      'include_dirs': [
        '<(DEPTH)',
      ],
      'sources': [
        'common/http_response_parser_test.cc',
        'common/http_to_spdy_converter_test.cc',
        'common/protocol_util_test.cc',
        'common/server_push_discovery_learner_test.cc',
        'common/server_push_discovery_session_test.cc',
        'common/shared_flow_control_window_test.cc',
        'common/spdy_frame_priority_queue_test.cc',
        'common/spdy_frame_queue_test.cc',
        'common/spdy_session_test.cc',
        'common/spdy_stream_test.cc',
        'common/spdy_to_http_converter_test.cc',
        'common/thread_pool_test.cc',
      ],
    },
    {
      'target_name': 'spdy_apache_test',
      'type': 'executable',
      'dependencies': [
        'spdy_apache',
        'spdy_common_testing',
        '<(DEPTH)/build/build_util.gyp:mod_spdy_version_header',
        '<(DEPTH)/testing/gtest.gyp:gtest',
        '<(DEPTH)/third_party/apache/apr/apr.gyp:apr',
        '<(DEPTH)/third_party/apache/aprutil/aprutil.gyp:aprutil',
      ],
      'include_dirs': [
        '<(DEPTH)',
      ],
      'sources': [
        'apache/filters/http_to_spdy_filter_test.cc',
        'apache/filters/server_push_filter_test.cc',
        'apache/filters/spdy_to_http_filter_test.cc',
        'apache/id_pool_test.cc',
        'apache/pool_util_test.cc',
        'apache/sockaddr_util_test.cc',
        'apache/testing/dummy_util_filter.cc',
        'apache/testing/spdy_apache_test_main.cc',
      ],
    },
  ],
}
