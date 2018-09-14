/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#pragma once

#include <osquery/expected.h>

#include <linux/bpf.h>

#include <vector>

namespace osquery {
namespace ebpf {

enum class ProgramError {
  SystemError = 1,
  NotSupportedBySystem = 2,
  InvalidArgument = 3,
  IncorrectProgram = 4,
  PermissionDenied = 5,
};

class Program final {
 public:
  ~Program();

  Program(Program const&) = delete;
  Program(Program&& from);

  Program& operator=(Program const&) = delete;
  Program& operator=(Program&& from);

  using Instructions = std::vector<union bpf_attr>;

  int fd() const {
    return fd_;
  }

  friend Expected<Program, ProgramError> loadProgram(
      enum bpf_prog_type prog_type, const Instructions& program);

 private:
  explicit Program(int const fd) : fd_(fd) {}

 private:
  int fd_ = -1;
};

Expected<Program, ProgramError> loadProgram(
    enum bpf_prog_type prog_type, const Program::Instructions& program);

} // namespace ebpf
} // namespace osquery
