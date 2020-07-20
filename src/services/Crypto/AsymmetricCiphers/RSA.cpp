//
// Created by antoine on 20/07/2020.
//

#include "RSA.h"

HCL::Crypto::RSA::RSA() {}

HCL::Crypto::RSA::RSA(const std::string &header, size_t &header_length) {}

std::string HCL::Crypto::RSA::GetHeader() {
  return GetIdBytes();
}

std::string HCL::Crypto::RSA::Encrypt(const std::string &key, const std::string &content) {
  return "WIP";
}

std::string HCL::Crypto::RSA::Decrypt(const std::string &key, const std::string &content) {
  return "WIP";
}