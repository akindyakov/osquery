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

#include <osquery/tests/test_util.h>

#include "osquery/core/base64.h"

namespace osquery {

class Base64Tests : public testing::Test {};

TEST_F(Base64Tests, encode_decode_padding_1) {
  std::string const unencoded = "HELLO";
  auto const encoded = base64::encode(unencoded);
  ASSERT_EQ(encoded, "SEVMTE8=");

  auto const unencoded2 = base64::decode(encoded);
  EXPECT_EQ(unencoded, unencoded2);
}

TEST_F(Base64Tests, encode_decode_empty_string) {
  std::string const unencoded = "";
  auto const encoded = base64::encode(unencoded);
  ASSERT_EQ(encoded.size(), 0U);

  auto const unencoded2 = base64::decode(encoded);
  EXPECT_EQ(unencoded, unencoded2);
}

TEST_F(Base64Tests, encode_decode_padding_0) {
  std::string const unencoded = "*+,-0@[']";
  auto const encoded = base64::encode(unencoded);
  ASSERT_EQ(encoded, "KissLTBAWydd");

  auto const unencoded2 = base64::decode(encoded);
  EXPECT_EQ(unencoded, unencoded2);
}

TEST_F(Base64Tests, encode_decode_padding_2) {
  std::string const unencoded = "!#$%&'()*+,-0@[]";
  auto const encoded = base64::encode(unencoded);
  ASSERT_EQ(encoded, "ISMkJSYnKCkqKywtMEBbXQ==");

  auto const unencoded2 = base64::decode(encoded);
  EXPECT_EQ(unencoded, unencoded2);
}

TEST_F(Base64Tests, decode_invalid_encoding) {
  auto const text = base64::decode("abc@");
  ASSERT_EQ(text.size(), 0U);
}

TEST_F(Base64Tests, tryDecode_valid_input) {
  auto const exp = base64::tryDecode("bGFuZw==");
  ASSERT_TRUE(exp.isValue());
  ASSERT_EQ(exp.get(), "lang");
}

TEST_F(Base64Tests, tryDecode_invalid_encoding) {
  auto const exp = base64::tryDecode("%&");
  ASSERT_TRUE(exp.isError());
  ASSERT_EQ(exp.getErrorCode(), base64::Error::InvalidEncoding);
}

} // namespace osquery
