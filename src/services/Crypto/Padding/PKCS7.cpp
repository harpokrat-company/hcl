//
// Created by neodar on 07/04/2020.
//

#include "PKCS7.h"

std::string HCL::Crypto::PKCS7::PadDataToSize(const std::string &data, size_t size) {
  uint8_t offset = size - data.length();

  return data + std::string(offset, (char) offset);
}
