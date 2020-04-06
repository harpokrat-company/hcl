//
// Created by neodar on 06/04/2020.
//

#include "ABlockCipherMode.h"
#include "../Factory.h"

HCL::Crypto::ABlockCipherMode::ABlockCipherMode(const std::string &header, size_t &header_length) {
  this->cipher_ = Factory<ABlockCipher>::GetInstanceFromHeader(header, header_length);
}
