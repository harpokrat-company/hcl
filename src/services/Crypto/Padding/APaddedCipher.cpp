//
// Created by neodar on 06/04/2020.
//

#include "APaddedCipher.h"
#include "../Factory.h"

HCL::Crypto::APaddedCipher::APaddedCipher(const std::string &header, size_t &header_length) {
  this->padding_ = Factory<APadding>::GetInstanceFromHeader(header, header_length);
}
