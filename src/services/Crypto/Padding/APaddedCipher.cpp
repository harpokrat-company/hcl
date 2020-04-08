//
// Created by neodar on 06/04/2020.
//

#include "APaddedCipher.h"
#include "../Factory.h"

HCL::Crypto::APaddedCipher::APaddedCipher(const std::string &header, size_t &header_length) {
  this->padding_ = Factory<APadding>::BuildTypedFromHeader(header, header_length);
}
std::string HCL::Crypto::APaddedCipher::GetHeader() {
  return padding_->GetHeader();
}

void HCL::Crypto::APaddedCipher::SetPadding(std::unique_ptr<AutoRegistrable> padding) {
  padding_ = AutoRegistrable::UniqueTo<APadding>(std::move(padding));
}
