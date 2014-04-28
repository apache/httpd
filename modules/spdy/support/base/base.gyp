# Copyright (c) 2009 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Base was branched from the chromium version to reduce the number of
# dependencies of this package.  Specifically, we would like to avoid
# depending on the chrome directory, which contains the chrome version
# and branding information.
# TODO: push this refactoring to chronium trunk.

{
  'variables': {
    'chromium_code': 1,
    'chromium_root': '<(DEPTH)/third_party/chromium/src',
  },
  'targets': [
    {
      'target_name': 'base',
      'type': '<(component)',
      'dependencies': [
        '<(DEPTH)/third_party/modp_b64/modp_b64.gyp:modp_b64',
        '<(chromium_root)/base/third_party/dynamic_annotations/dynamic_annotations.gyp:dynamic_annotations',
      ],
      'sources': [
        '<(chromium_root)/base/at_exit.cc',
        '<(chromium_root)/base/atomicops_internals_x86_gcc.cc',
        '<(chromium_root)/base/base_switches.cc',
        '<(chromium_root)/base/callback_internal.cc',
        '<(chromium_root)/base/command_line.cc',
        '<(chromium_root)/base/debug/alias.cc',
        '<(chromium_root)/base/debug/debugger.cc',
        '<(chromium_root)/base/debug/debugger_posix.cc',
        '<(chromium_root)/base/debug/debugger_win.cc',
        '<(chromium_root)/base/debug/stack_trace.cc',
        '<(chromium_root)/base/debug/stack_trace_posix.cc',
        '<(chromium_root)/base/debug/stack_trace_win.cc',
        '<(chromium_root)/base/files/file_path.cc',
        '<(chromium_root)/base/files/file_path_constants.cc',
        '<(chromium_root)/base/lazy_instance.cc',
        '<(chromium_root)/base/location.cc',
        '<(chromium_root)/base/logging.cc',
        '<(chromium_root)/base/logging_win.cc',
        '<(chromium_root)/base/mac/foundation_util.mm',
        '<(chromium_root)/base/memory/ref_counted.cc',
        '<(chromium_root)/base/memory/singleton.cc',
        '<(chromium_root)/base/metrics/stats_counters.cc',
        'metrics/stats_table.cc',
        '<(chromium_root)/base/pickle.cc',
        '<(chromium_root)/base/process/process_handle_linux.cc',
        '<(chromium_root)/base/process/process_handle_mac.cc',
        '<(chromium_root)/base/process/process_handle_posix.cc',
        '<(chromium_root)/base/process/process_handle_win.cc',
        '<(chromium_root)/base/profiler/alternate_timer.cc',
        '<(chromium_root)/base/profiler/tracked_time.cc',
        '<(chromium_root)/base/safe_strerror_posix.cc',
        '<(chromium_root)/base/strings/string16.cc',
        '<(chromium_root)/base/strings/string16.h',
        '<(chromium_root)/base/strings/string_number_conversions.cc',
        '<(chromium_root)/base/strings/string_piece.cc',
        '<(chromium_root)/base/strings/string_split.cc',
        '<(chromium_root)/base/strings/string_util.cc',
        '<(chromium_root)/base/strings/string_util_constants.cc',
        '<(chromium_root)/base/strings/stringprintf.cc',
        '<(chromium_root)/base/strings/sys_string_conversions_posix.cc',
        '<(chromium_root)/base/strings/sys_string_conversions_mac.mm',
        '<(chromium_root)/base/strings/sys_string_conversions_win.cc',
        '<(chromium_root)/base/strings/utf_string_conversion_utils.cc',
        '<(chromium_root)/base/strings/utf_string_conversions.cc',
        '<(chromium_root)/base/synchronization/condition_variable_posix.cc',
        '<(chromium_root)/base/synchronization/condition_variable_win.cc',
        '<(chromium_root)/base/synchronization/lock.cc',
        '<(chromium_root)/base/synchronization/lock_impl_posix.cc',
        '<(chromium_root)/base/synchronization/lock_impl_win.cc',
        '<(chromium_root)/base/synchronization/waitable_event_posix.cc',
        '<(chromium_root)/base/synchronization/waitable_event_win.cc',
        '<(chromium_root)/base/third_party/dmg_fp/g_fmt.cc',
        '<(chromium_root)/base/third_party/dmg_fp/dtoa_wrapper.cc',
        '<(chromium_root)/base/third_party/icu/icu_utf.cc',
        '<(chromium_root)/base/third_party/nspr/prtime.cc',
        '<(chromium_root)/base/threading/platform_thread_mac.mm',
        '<(chromium_root)/base/threading/platform_thread_linux.cc',
        '<(chromium_root)/base/threading/platform_thread_posix.cc',
        '<(chromium_root)/base/threading/platform_thread_win.cc',
        '<(chromium_root)/base/threading/thread_collision_warner.cc',
        '<(chromium_root)/base/threading/thread_id_name_manager.cc',
        '<(chromium_root)/base/threading/thread_local_posix.cc',
        '<(chromium_root)/base/threading/thread_local_win.cc',
        '<(chromium_root)/base/threading/thread_local_storage_posix.cc',
        '<(chromium_root)/base/threading/thread_local_storage_win.cc',
        '<(chromium_root)/base/threading/thread_restrictions.cc',
        '<(chromium_root)/base/time/time.cc',
        '<(chromium_root)/base/time/time_mac.cc',
        '<(chromium_root)/base/time/time_posix.cc',
        '<(chromium_root)/base/time/time_win.cc',
        '<(chromium_root)/base/tracked_objects.cc',
        '<(chromium_root)/base/vlog.cc',
        '<(chromium_root)/base/win/registry.cc',
        '<(chromium_root)/base/win/win_util.cc',
        '<(chromium_root)/base/win/windows_version.cc',
      ],
      'include_dirs': [
        '<(chromium_root)',
        '<(DEPTH)',
      ],
      'direct_dependent_settings': {
        'include_dirs': [
          '<(chromium_root)',
          '<(DEPTH)',
        ],
      },
      'conditions': [
        ['OS != "win"', {
          'sources/': [ ['exclude', '^win/'] ],
        }],
        [ 'OS == "win"', {
          'sources!': [
            '<(chromium_root)/base/string16.cc',
          ],
        }],
        ['OS == "linux"', {
          'cflags': [
            '-Wno-write-strings',
            '-Wno-error',
          ],
          'link_settings': {
            'libraries': [
              # We need rt for clock_gettime().
              '-lrt',
            ],
          },
        }],
      ],
    },
  ],
}
