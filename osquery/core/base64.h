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

#include <string>

#include <osquery/expected.h>

namespace osquery {

namespace base64 {

enum class Error {
  InvalidEncoding = 1,
};

/**
 * @brief Decode a base64 encoded string.
 *
 * @param encoded The encode base64 string.
 * @return Decoded string.
 */
std::string decode(std::string encoded);

/**
 * @brief Try to decode a base64 encoded string.
 * @param encoded The base64 encoded string.
 * @return Expected with decoded string or error in case of wrong encoding.
 */
Expected<std::string, Error> tryDecode(std::string encoded);

/**
 * @brief Encode a  string.
 *
 * @param A string to encode.
 * @return Encoded string.
 */
std::string encode(const std::string& unencoded);

} // namespace base64

} // namespace osquery
