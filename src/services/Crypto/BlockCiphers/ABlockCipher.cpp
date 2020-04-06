//
// Created by neodar on 06/04/2020.
//

#include "ABlockCipher.h"
#include "../Factory.h"

HCL::Crypto::ABlockCipher::ABlockCipher(const std::string &header, size_t &header_length) {
  key_stretching_ = Factory<AKeyStretching>::GetInstanceFromHeader(header, header_length);
}
