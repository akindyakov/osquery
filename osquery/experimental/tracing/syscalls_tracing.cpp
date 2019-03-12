/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/experimental/tracing/syscalls_tracing.h>

#include <osquery/experimental/events_stream/events_stream.h>

#include <osquery/events/linux/probes/probes.h>

#include <osquery/dispatcher.h>
#include <osquery/flags.h>
#include <osquery/logger.h>

#include <osquery/utils/expected/expected.h>
#include <osquery/utils/json/json.h>
#include <osquery/utils/system/time.h>

#include <boost/io/detail/quoted_manip.hpp>

namespace osquery {

DEFINE_bool(enable_experimental_tracing,
            false,
            "Experimental syscalls tracing");

namespace experimental {
namespace tracing {

namespace {

enum class Error {
  InitialisationProblem = 1,
  RuntimeProblem = 2,
  DeinitializationProblem = 3,
};

ExpectedSuccess<Error> runSyscallTracing() {
  auto probes_exp = ::osquery::events::LinuxProbesControl::spawn();
  if (probes_exp.isError()) {
    return createError(Error::InitialisationProblem,
                       "linux probes control spawn failed",
                       probes_exp.takeError());
  }
  auto probes = probes_exp.take();
  auto kill_trace_on_exp = probes.traceKill();
  if (kill_trace_on_exp.isError()) {
    return createError(Error::InitialisationProblem,
                       "kill tracing initialisation failed",
                       kill_trace_on_exp.takeError());
  }
  auto setuid_trace_on_exp = probes.traceSetuid();
  if (setuid_trace_on_exp.isError()) {
    return createError(Error::InitialisationProblem,
                       "setuid tracing initialisation failed",
                       setuid_trace_on_exp.takeError());
  }
  auto output_batch = ebpf::PerfOutputsPoll<
      ::osquery::events::syscall::Event>::MessageBatchType{};
  auto event_joiner = ::osquery::events::syscall::EnterExitJoiner{};
  while (true) {
    auto status = probes.getReader().read(output_batch);
    if (status.isError()) {
      return createError(
          Error::RuntimeProblem, "event read failed", status.takeError());
    }
    for (const auto& event : output_batch) {
      auto final_event = event_joiner.join(event);
      if (final_event) {
        auto event_json = JSON{};
        auto event_str = std::string{};
        event_json.add("time", getUnixTime());
        event_json.add("pid", final_event->pid);
        event_json.add("tgid", final_event->tgid);
        event_json.add("return", final_event->return_value);
        if (final_event->type ==
            ::osquery::events::syscall::EventType::KillEnter) {
          event_json.add("type", "kill");
          event_json.add("uid", final_event->body.kill_enter.uid);
          event_json.add("gid", final_event->body.kill_enter.gid);
          event_json.add("comm", final_event->body.kill_enter.comm);
          event_json.add("arg_pid", final_event->body.kill_enter.arg_pid);
          event_json.add("arg_sig", final_event->body.kill_enter.arg_sig);
        } else if (final_event->type ==
                   ::osquery::events::syscall::EventType::SetuidEnter) {
          event_json.add("type", "setuid");
          event_json.add("uid", final_event->body.setuid_enter.uid);
          event_json.add("gid", final_event->body.setuid_enter.gid);
          event_json.add("comm", final_event->body.setuid_enter.comm);
          event_json.add("arg_uid", final_event->body.setuid_enter.arg_uid);
        } else {
          event_json.add("type", "unknown");
        }
        auto status_json_to_string = event_json.toString(event_str);
        if (status_json_to_string.ok()) {
          osquery::experimental::events::dispatchSerializedEvent(event_str);
        } else {
          LOG(ERROR) << "Event serialisation failed: "
                     << status_json_to_string.what();
        }
      }
    }
  }
  return Success{};
}

class SyscallTracingRannable : public ::osquery::InternalRunnable {
 public:
  explicit SyscallTracingRannable()
      : ::osquery::InternalRunnable("SyscallTracingRannable") {}

  void start() override {
    auto ret = runSyscallTracing();
    if (ret.isError()) {
      LOG(ERROR) << "Experimental syscall tracing failed: "
                 << ret.getError().getMessage();
    }
  }

  void stop() override {}
};

} // namespace

void init() {
  if (FLAGS_enable_experimental_tracing) {
    LOG(INFO) << "Experimental syscall tracing is enabled";
    Dispatcher::addService(std::make_shared<SyscallTracingRannable>());
  }
}

} // namespace tracing
} // namespace experimental
} // namespace osquery
