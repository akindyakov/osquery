/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <gtest/gtest.h>

#include <osquery/events/linux/probes/ebpf_tracepoint.h>

namespace osquery {
namespace {

class EbpfTracepointTests : public testing::Test {};

TEST_F(EbpfTracepointTests, invalid_args) {
  auto ebpf_tracepoint_exp = events::EbpfTracepoint::load(-1, -1);
  ASSERT_TRUE(ebpf_tracepoint_exp.isError());
}

} // namespace
} // namespace osquery
