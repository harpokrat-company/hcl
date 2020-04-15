//
// Created by neodar on 07/04/2020.
//

#include "PKCS7.h"

std::string HCL::Crypto::PKCS7::PadDataToSize(const std::string &data, size_t size) {
  uint8_t offset = size - data.length();

  return data + std::string(offset, (char) offset);
}

std::string HCL::Crypto::PKCS7::RemovePadding(const std::string &data) {
  uint8_t offset = data[data.length() - 1];

  for (size_t i = data.length() - offset; i < data.length(); ++i) {
    if (data[i] != (char) offset) {
      throw std::runtime_error(GetError("remove padding", "Incorrect padding"));
    }
  }
  return data.substr(0, data.length() - offset);
}

std::string HCL::Crypto::PKCS7::GetHeader() {
  return GetIdBytes();
}
