//
// Created by neodar on 06/04/2020.
//

#include "PaddedCipher.h"
#include "../Factory.h"

HCL::Crypto::PaddedCipher::PaddedCipher(const std::string &header, size_t &header_length) {
  this->padding_ = Factory<APadding>::GetInstanceFromHeader(header, header_length);
}
