// Copyright 2010 Google Inc.
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

#include "mod_spdy/apache/log_message_handler.h"

#include <limits>
#include <string>

#include "httpd.h"
// When HAVE_SYSLOG is defined, apache http_log.h will include syslog.h, which
// #defined LOG_* as numbers. This conflicts with what we are using those here.
#undef HAVE_SYSLOG
#include "http_log.h"

#include "base/debug/debugger.h"
#include "base/debug/stack_trace.h"
#include "base/logging.h"
#include "base/threading/thread_local.h"
#include "mod_spdy/apache/pool_util.h"
#include "mod_spdy/common/spdy_stream.h"
#include "mod_spdy/common/version.h"

// Make sure we don't attempt to use LOG macros here, since doing so
// would cause us to go into an infinite log loop.
#undef LOG
#define LOG USING_LOG_HERE_WOULD_CAUSE_INFINITE_RECURSION

namespace {

class LogHandler;

const char* const kLogMessagePrefix =
    "[mod_spdy/" MOD_SPDY_VERSION_STRING "-" LASTCHANGE_STRING "] ";

apr_pool_t* log_pool = NULL;
base::ThreadLocalPointer<LogHandler>* gThreadLocalLogHandler = NULL;

const int kMaxInt = std::numeric_limits<int>::max();
int log_level_cutoff = kMaxInt;

class LogHandler {
 public:
  explicit LogHandler(LogHandler* parent) : parent_(parent) {}
  virtual ~LogHandler() {}
  virtual void Log(int log_level, const std::string& message) = 0;
  LogHandler* parent() const { return parent_; }
 private:
  LogHandler* parent_;
  DISALLOW_COPY_AND_ASSIGN(LogHandler);
};

// Log a message with the given LogHandler; if the LogHandler is NULL, fall
// back to using ap_log_perror.
void LogWithHandler(LogHandler* handler, int log_level,
                    const std::string& message) {
  if (handler != NULL) {
    handler->Log(log_level, message);
  } else {
    // ap_log_perror only prints messages with a severity of at least NOTICE,
    // so if we're falling back to ap_log_perror (which should be rare) then
    // force the log_level to a verbosity of NOTICE or lower.
    COMPILE_ASSERT(APLOG_DEBUG > APLOG_NOTICE,
                   higher_verbosity_is_higher_number);
    ap_log_perror(APLOG_MARK, std::min(log_level, APLOG_NOTICE), APR_SUCCESS,
                  log_pool, "%s", message.c_str());
  }
}

void PopLogHandler() {
  CHECK(gThreadLocalLogHandler);
  LogHandler* handler = gThreadLocalLogHandler->Get();
  CHECK(handler);
  gThreadLocalLogHandler->Set(handler->parent());
  delete handler;
}

class ServerLogHandler : public LogHandler {
 public:
  ServerLogHandler(LogHandler* parent, server_rec* server)
      : LogHandler(parent), server_(server) {}
  virtual void Log(int log_level, const std::string& message) {
    ap_log_error(APLOG_MARK, log_level, APR_SUCCESS, server_,
                 "%s", message.c_str());
  }
 private:
  server_rec* const server_;
  DISALLOW_COPY_AND_ASSIGN(ServerLogHandler);
};

class ConnectionLogHandler : public LogHandler {
 public:
  ConnectionLogHandler(LogHandler* parent, conn_rec* connection)
      : LogHandler(parent), connection_(connection) {}
  virtual void Log(int log_level, const std::string& message) {
    ap_log_cerror(APLOG_MARK, log_level, APR_SUCCESS, connection_,
                  "%s", message.c_str());
  }
 private:
  conn_rec* const connection_;
  DISALLOW_COPY_AND_ASSIGN(ConnectionLogHandler);
};

class StreamLogHandler : public LogHandler {
 public:
  StreamLogHandler(LogHandler* parent, conn_rec* connection,
                   const mod_spdy::SpdyStream* stream)
      : LogHandler(parent), connection_(connection), stream_(stream) {}
  virtual void Log(int log_level, const std::string& message) {
    ap_log_cerror(APLOG_MARK, log_level, APR_SUCCESS, connection_,
                  "[stream %d] %s", static_cast<int>(stream_->stream_id()),
                  message.c_str());
  }
 private:
  conn_rec* const connection_;
  const mod_spdy::SpdyStream* const stream_;
  DISALLOW_COPY_AND_ASSIGN(StreamLogHandler);
};

int GetApacheLogLevel(int severity) {
  switch (severity) {
    case logging::LOG_INFO:
      return APLOG_INFO;
    case logging::LOG_WARNING:
      return APLOG_WARNING;
    case logging::LOG_ERROR:
      return APLOG_ERR;
    case logging::LOG_ERROR_REPORT:
      return APLOG_CRIT;
    case logging::LOG_FATAL:
      return APLOG_ALERT;
    default:  // For VLOG()s
      return APLOG_DEBUG;
  }
}

bool LogMessageHandler(int severity, const char* file, int line,
                       size_t message_start, const std::string& str) {
  const int this_log_level = GetApacheLogLevel(severity);

  std::string message(kLogMessagePrefix);
  message.append(str);
  if (severity == logging::LOG_FATAL) {
    if (base::debug::BeingDebugged()) {
      base::debug::BreakDebugger();
    } else {
      base::debug::StackTrace trace;
      std::ostringstream stream;
      trace.OutputToStream(&stream);
      message.append(stream.str());
    }
  }

  // Trim the newline off the end of the message string.
  size_t last_msg_character_index = message.length() - 1;
  if (message[last_msg_character_index] == '\n') {
    message.resize(last_msg_character_index);
  }

  if (this_log_level <= log_level_cutoff || log_level_cutoff == kMaxInt) {
    LogWithHandler(gThreadLocalLogHandler->Get(), this_log_level, message);
  }

  if (severity == logging::LOG_FATAL) {
    // Crash the process to generate a dump.
    base::debug::BreakDebugger();
  }

  return true;
}

// Include PID and TID in each log message.
bool kShowProcessId = true;
bool kShowThreadId = true;

// Disabled since this information is already included in the apache
// log line.
bool kShowTimestamp = false;

// Disabled by default due to CPU cost. Enable to see high-resolution
// timestamps in the logs.
bool kShowTickcount = false;

}  // namespace

namespace mod_spdy {

ScopedServerLogHandler::ScopedServerLogHandler(server_rec* server) {
  CHECK(gThreadLocalLogHandler);
  gThreadLocalLogHandler->Set(new ServerLogHandler(
      gThreadLocalLogHandler->Get(), server));
}

ScopedServerLogHandler::~ScopedServerLogHandler() {
  PopLogHandler();
}

ScopedConnectionLogHandler::ScopedConnectionLogHandler(conn_rec* connection) {
  CHECK(gThreadLocalLogHandler);
  gThreadLocalLogHandler->Set(new ConnectionLogHandler(
      gThreadLocalLogHandler->Get(), connection));
}

ScopedConnectionLogHandler::~ScopedConnectionLogHandler() {
  PopLogHandler();
}

ScopedStreamLogHandler::ScopedStreamLogHandler(conn_rec* slave_connection,
                                               const SpdyStream* stream) {
  CHECK(gThreadLocalLogHandler);
  gThreadLocalLogHandler->Set(new StreamLogHandler(
      gThreadLocalLogHandler->Get(), slave_connection, stream));
}

ScopedStreamLogHandler::~ScopedStreamLogHandler() {
  PopLogHandler();
}

void InstallLogMessageHandler(apr_pool_t* pool) {
  log_pool = pool;
  gThreadLocalLogHandler = new base::ThreadLocalPointer<LogHandler>();
  PoolRegisterDelete(pool, gThreadLocalLogHandler);
  logging::SetLogItems(kShowProcessId,
                       kShowThreadId,
                       kShowTimestamp,
                       kShowTickcount);
  logging::SetLogMessageHandler(&LogMessageHandler);
}

void SetLoggingLevel(int apache_log_level, int vlog_level) {
  switch (apache_log_level) {
    case APLOG_EMERG:
    case APLOG_ALERT:
      logging::SetMinLogLevel(logging::LOG_FATAL);
      break;
    case APLOG_CRIT:
      logging::SetMinLogLevel(logging::LOG_ERROR_REPORT);
      break;
    case APLOG_ERR:
      logging::SetMinLogLevel(logging::LOG_ERROR);
      break;
    case APLOG_WARNING:
      logging::SetMinLogLevel(logging::LOG_WARNING);
      break;
    case APLOG_NOTICE:
    case APLOG_INFO:
    case APLOG_DEBUG:
    default:
      logging::SetMinLogLevel(std::min(logging::LOG_INFO, -vlog_level));
      break;
  }
}

}  // namespace mod_spdy
