# Copyright (c) 2009 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

{
  'variables': {
    'chromium_code': 1,
    'chromium_root': '<(DEPTH)/third_party/chromium/src',
  },
  'targets': [
    {
      'target_name': 'instaweb_util',
      'type': '<(library)',
      'dependencies': [
        '<(DEPTH)/base/base.gyp:base',
      ],
      'include_dirs': [
        '<(DEPTH)',
      ],
      'export_dependent_settings': [
        '<(DEPTH)/base/base.gyp:base',
      ],
      'sources': [
        # TODO(mdsteele): Add sources here as we need them.
        'instaweb/util/function.cc',
      ],
    },
    {
      'target_name': 'spdy',
      'type': '<(library)',
      'dependencies': [
        '<(DEPTH)/base/base.gyp:base',
        '<(DEPTH)/third_party/zlib/zlib.gyp:zlib',
      ],
      'export_dependent_settings': [
        '<(DEPTH)/base/base.gyp:base',
      ],
      'include_dirs': [
        '<(DEPTH)',
        '<(chromium_root)',
      ],
      'sources': [
        '<(chromium_root)/net/spdy/buffered_spdy_framer.cc',
        '<(chromium_root)/net/spdy/spdy_frame_builder.cc',
        '<(chromium_root)/net/spdy/spdy_frame_reader.cc',
        '<(chromium_root)/net/spdy/spdy_framer.cc',
        '<(chromium_root)/net/spdy/spdy_protocol.cc',
      ],
    },
  ],
}
