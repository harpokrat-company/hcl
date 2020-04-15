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
    throw std::runtime_error(GetDependencyUnsetError("get header", "Padding"));
  }
  return padding_->GetHeader();
}

void HCL::Crypto::APaddedCipher::SetPadding(std::unique_ptr<ACryptoElement> padding) {
  padding_ = ACryptoElement::UniqueTo<APadding>(std::move(padding));
}

bool HCL::Crypto::APaddedCipher::IsPaddingSet() const {
  return !!padding_;
}

HCL::Crypto::ACryptoElement &HCL::Crypto::APaddedCipher::GetPadding() const {
  if (!IsPaddingSet()) {
    throw std::runtime_error(GetDependencyUnsetError("get padding", "Padding"));
  }
  return *padding_;
}
