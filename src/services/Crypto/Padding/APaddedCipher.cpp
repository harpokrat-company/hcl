//
// Created by neodar on 06/04/2020.
//

#include "APaddedCipher.h"
#include "../Factory.h"

HCL::Crypto::APaddedCipher::APaddedCipher(const std::string &header, size_t &header_length) {
  this->padding_ = Factory<APadding>::BuildTypedFromHeader(header, header_length);
}
std::string HCL::Crypto::APaddedCipher::GetHeader() {
  if (!padding_) {
    throw std::runtime_error("APaddedCipher error: Padding is not set");
  }
  return padding_->GetHeader();
}

void HCL::Crypto::APaddedCipher::SetPadding(std::unique_ptr<ACryptoElement> padding) {
  padding_ = ACryptoElement::UniqueTo<APadding>(std::move(padding));
}
