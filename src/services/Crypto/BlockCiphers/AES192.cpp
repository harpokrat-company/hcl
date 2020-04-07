//
// Created by neodar on 07/04/2020.
//

#include "AES192.h"

const std::string HCL::Crypto::AES192::name = "aes192";

std::string HCL::Crypto::AES192::GetHeader() {
  return GetIdBytes() + key_stretching_->GetHeader();
}
