//
// Created by neodar on 06/04/2020.
//

#include "ABlockCipherMode.h"
#include "../Factory.h"

HCL::Crypto::ABlockCipherMode::ABlockCipherMode(const std::string &header, size_t &header_length) {
  cipher_ = Factory<ABlockCipher>::BuildTypedFromHeader(header, header_length);
}

std::string HCL::Crypto::ABlockCipherMode::GetHeader() {
  if (!cipher_) {
    throw std::runtime_error("ABlockCipherMode error: Cipher is not set");
  }
  return cipher_->GetHeader();
}

void HCL::Crypto::ABlockCipherMode::SetCipher(std::unique_ptr<ACryptoElement> cipher) {
  cipher_ = ACryptoElement::UniqueTo<ABlockCipher>(std::move(cipher));
}
