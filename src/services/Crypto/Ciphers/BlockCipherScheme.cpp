//
// Created by neodar on 06/04/2020.
//

#include "BlockCipherScheme.h"

HCL::Crypto::BlockCipherScheme::BlockCipherScheme(const std::string &header, size_t &header_length) {
  // TODO Parse header to get Block cipher, Mode of operation and Key derivation
}

std::string HCL::Crypto::BlockCipherScheme::Encrypt(const std::string &password, const std::string &content) {
  // TODO
  return std::__cxx11::string();
}

std::string HCL::Crypto::BlockCipherScheme::Decrypt(const std::string &password, const std::string &content) {
  // TODO
  return std::__cxx11::string();
}
