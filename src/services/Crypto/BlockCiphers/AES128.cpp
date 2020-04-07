//
// Created by neodar on 07/04/2020.
//

#include "AES128.h"

const std::string HCL::Crypto::AES128::name = "aes128";

std::string HCL::Crypto::AES128::GetHeader() {
  return GetIdBytes() + key_stretching_->GetHeader();
}
