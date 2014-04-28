#!/usr/bin/env python

# Copyright 2012 Google Inc.
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

# A simple script for load-testing mod_spdy (or any other SPDY server).  For
# example, to hit the server with 150 simultaneous SPDY clients, each fetching
# the URLs https://example.com/ and https://example.com/image.jpg, you would
# run:
#
#  $ ./loadtest.py spdy 150 https://example.com/ https://example.com/image.jpg
#
# To run the same test with plain HTTPS clients instead of SPDY clients (for
# comparison), you would run:
#
#  $ ./loadtest.py https 150 https://example.com/ https://example.com/image.jpg
#
# Press Ctrl-C to stop the test.
#
# You must have spdycat (https://github.com/tatsuhiro-t/spdylay) installed and
# on your $PATH in order to run SPDY tests, and you must have curl installed in
# order to run HTTPS or HTTP tests.

from __future__ import division  # Always convert ints to floats for / operator
from __future__ import print_function  # Treat print as function, not keyword

import re
import subprocess
import sys
import time

#=============================================================================#

def print_usage_and_quit():
  sys.stderr.write('Usage: {0} TYPE MAX_CLIENTS URL...\n'.format(sys.argv[0]))
  sys.stderr.write('TYPE must be one of "spdy", "https", or "http"\n')
  sys.stderr.write('MAX_CLIENTS must be a positive integer\n')
  sys.exit(1)

def with_scheme(url, scheme):
  """Given a URL string, return a new URL string with the given scheme."""
  if re.match(r'^[a-zA-Z0-9]+:', url):
    return re.sub(r'^[a-zA-Z0-9]+:', scheme + ':', url)
  elif url.startswith('//'):
    return scheme + ':' + url
  else:
    return scheme + '://' + url


class ClientProcess (object):
  """A client subprocess that will try to load the URLs from the server."""

  def __init__(self, key, command, factory):
    self.__key = key
    self.__child = subprocess.Popen(command, stdout=open('/dev/null', 'wb'))
    self.__start_time = time.time()
    self.__factory = factory

  def get_key(self):
    return self.__key

  def get_start_time(self):
    return self.__start_time

  def check_done(self):
    """If the client is done, print time and return True, else return False."""
    code = self.__child.poll()
    if code is None:
      return False
    else:
      duration = time.time() - self.__start_time
      self.__factory._client_finished(self.__key, code, duration)
      return True

  def kill(self):
    """Shut down this client."""
    self.__child.kill()


class ClientFactory (object):
  """A factory for ClientProcess objects, that also tracks stats."""

  def __init__(self, command):
    """Create a factory that will use the given command for subprocesses."""
    self.__command = command
    self.num_started = 0
    self.num_finished = 0
    self.max_duration = 0.0
    self.total_duration = 0.0

  def new_client(self):
    """Create and return a new ClientProcess."""
    self.num_started += 1
    return ClientProcess(key=self.num_started, command=self.__command,
                         factory=self)

  def _client_finished(self, key, code, duration):
    """Called by each ClientProcess when it finishes."""
    self.num_finished += 1
    self.max_duration = max(self.max_duration, duration)
    self.total_duration += duration
    print('Client {0} exit {1} after {2:.3f}s'.format(key, code, duration))

#=============================================================================#

if len(sys.argv) < 4:
  print_usage_and_quit()

# Determine what type of test we're doing and what URL scheme to use.
TYPE = sys.argv[1].lower()
if TYPE not in ['spdy', 'https', 'http']:
  print_usage_and_quit()
SCHEME = 'https' if TYPE == 'spdy' else TYPE

# Determine how many clients to have at once.
try:
  MAX_CLIENTS = int(sys.argv[2])
except ValueError:
  print_usage_and_quit()
if MAX_CLIENTS < 1:
  print_usage_and_quit()

# Collect the URLs to fetch from.
URLS = []
for url in sys.argv[3:]:
  URLS.append(with_scheme(url, SCHEME))

# Put together the subprocess command to issue for each client.
if TYPE == 'spdy':
  # The -n flag tells spdycat throw away the downloaded data without saving it.
  COMMAND = ['spdycat', '-n'] + URLS
else:
  # The -s flag tells curl to be silent (don't display progress meter); the -k
  # flag tells curl to ignore certificate errors (e.g. self-signed certs).
  COMMAND = ['curl', '-sk'] + URLS

# Print out a summary of the test we'll be doing before we start.
print('TYPE={0}'.format(TYPE))
print('URLS ({0}):'.format(len(URLS)))
for url in URLS:
    print('  ' + url)
print('MAX_CLIENTS={0}'.format(MAX_CLIENTS))

# Run the test.
factory = ClientFactory(COMMAND)
clients = []
try:
  # Start us off with an initial batch of clients.
  for index in xrange(MAX_CLIENTS):
    clients.append(factory.new_client())
  # Each time a client finishes, replace it with a new client.
  # TODO(mdsteele): This is a busy loop, which isn't great.  What we want is to
  #   sleep until one or more children are done.  Maybe we could do something
  #   clever that would allow us to do a select() call here or something.
  while True:
    for index in xrange(MAX_CLIENTS):
      if clients[index].check_done():
        clients[index] = factory.new_client()
# Stop when the user hits Ctrl-C, and print a summary of the results.
except KeyboardInterrupt:
  print()
  if clients:
    slowpoke = min(clients, key=(lambda c: c.get_key()))
    print('Earliest unfinished client, {0}, not done after {1:.3f}s'.format(
        slowpoke.get_key(), time.time() - slowpoke.get_start_time()))
  if factory.num_finished > 0:
    print('Avg time per client: {0:.3f}s ({1} started, {2} completed)'.format(
        factory.total_duration / factory.num_finished,
        factory.num_started, factory.num_finished))
    print('Max time per client: {0:.3f}s'.format(factory.max_duration))
    print("URLs served per second: {0:.3f}".format(
        factory.num_finished * len(URLS) / factory.total_duration))
for client in clients:
  client.kill()

#=============================================================================#
