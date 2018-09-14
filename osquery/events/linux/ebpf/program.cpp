/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include "osquery/events/linux/ebpf/program.h"
#include "osquery/events/linux/ebpf/system.h"

#include <osquery/core/map_take.h>

#include <boost/io/detail/quoted_manip.hpp>

#include <unordered_map>

#include <cerrno>
#include <cstring>

namespace osquery {
namespace ebpf {

namespace {

constexpr std::size_t kLogSize = 1 << 12;

auto const kKernelErrorDecryption = std::unordered_map<int, std::string>{
    {E2BIG,
     "The eBPF program is too large or a map reached the max_entries limit "
     "(maximum number of elements)."},
    {EACCES,
     "For BPF_PROG_LOAD, even though all program instructions are valid, the "
     "program has been rejected because it was deemed unsafe. This may be "
     "because it may have accessed a disallowed memory region or an "
     "uninitialized stack/register or because the function constraints don't "
     "match the actual types or because there was a misaligned memory access."},
    {EFAULT,
     "One of the pointers (key or value or log_buf or insns) is outside the "
     "accessible address space."},
    {EINVAL,
     "For BPF_PROG_LOAD, indicates an attempt to load an invalid program. eBPF "
     "programs can be deemed invalid due to unrecognized instructions, the use "
     "of reserved fields, jumps out of range, infinite loops or calls of "
     "unknown functions."},
    {EPERM,
     "The call was made without sufficient privilege (without the "
     "CAP_SYS_ADMIN capability)."},
};

ProgramError kernelErrorCodeToProgramError(int kernel_error) {
  auto err_code = ProgramError::SystemError;
  if (kernel_error == EACCES || kernel_error == EINVAL) {
    err_code = ProgramError::IncorrectProgram;
  } else if (kernel_error == EPERM) {
    err_code = ProgramError::PermissionDenied;
  } else if (kernel_error == ENOSYS) {
    err_code = ProgramError::NotSupportedBySystem;
  }
  return err_code;
}

} // namespace

Program::~Program() {
  if (fd_ >= 0) {
    close(fd_);
  }
}

Program::Program(Program&& from) : fd_(from.fd_) {
  from.fd_ = -1;
}

Program& Program::operator=(Program&& from) {
  if (fd_ >= 0) {
    close(fd_);
    fd_ = -1;
  }
  std::swap(fd_, from.fd_);
  return *this;
}

Expected<Program, ProgramError> loadProgram(
    enum bpf_prog_type prog_type, const Program::Instructions& program) {
  char const* license = "GPLv2";
  union bpf_attr attr;
  memset(&attr, 0, sizeof(union bpf_attr));
  attr.prog_type = prog_type;
  attr.insns = reinterpret_cast<std::uint64_t>(program.data());
  attr.insn_cnt = static_cast<std::uint32_t>(program.size());
  attr.license = reinterpret_cast<std::uint64_t>(license);
  attr.kern_version = kMinimalLinuxVersionCode;

  int ret = syscall(__NR_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
  if (ret > -1) {
    return Program(ret);
  }
  auto const kernel_error = errno;
  auto const err_code = kernelErrorCodeToProgramError(kernel_error);
  auto log_buffer = std::string(kLogSize, '\0');

  attr.log_buf = reinterpret_cast<std::uint64_t>(log_buffer.data());
  attr.log_size = kLogSize;
  attr.log_level = 1;
  // let's try again with logging
  ret = syscall(__NR_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
  if (ret > -1) {
    return Program(ret);
  }
  log_buffer.resize(log_buffer.find('\0'));

  return createError(err_code,
                     "Loading an eBPF program into the kernel failed: ")
         << boost::io::quoted(strerror(kernel_error)) << ", "
         << boost::io::quoted(tryTakeCopy(kKernelErrorDecryption, kernel_error)
                                  .takeOr(std::string{"..."}))
         << ", " << boost::io::quoted(log_buffer);
}

} // namespace ebpf
} // namespace osquery
