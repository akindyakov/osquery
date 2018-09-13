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

class Program {
 public:
  ~Program() {
    if (fd_ >= 0) {
      close(fd_);
    }
  }

  Program(Program const&) = delete;
  Program(Program&& from) : fd_(from.fd_) {
    from.fd_ = -1;
  }

  Program& operator=(Program const&) = delete;
  Program& operator=(Program&& from) {
    if (fd_ >= 0) {
      close(fd_);
      fd_ = -1;
    }
    std::swap(fd_, from.fd_);
    return *this;
  }

  using Instructions = std::vector<union bpf_attr>;

  int fd() const {
    return fd_;
  }

  friend Expected<Program, ProgramError> loadProgram(
      bpf_prog_type prog_type, const Instructions& ebpf_program);

 private:
  explicit Program(int const fd) : fd_(fd) {}

 private:
  int fd_ = -1;
};

Expected<Program, ProgramError> loadProgram(
    bpf_prog_type prog_type, const Program::Instructions& ebpf_program);

} // namespace ebpf
} // namespace osquery
