//
// Created by neodar on 06/04/2020.
//

#include "ABlockCipherMode.h"
#include "../Factory.h"

HCL::Crypto::ABlockCipherMode::ABlockCipherMode(const std::string &header, size_t &header_length) {
  cipher_ = Factory<ABlockCipher>::BuildTypedFromHeader(header, header_length);
}

std::string HCL::Crypto::ABlockCipherMode::GetHeader() {
  return cipher_->GetHeader();
}
