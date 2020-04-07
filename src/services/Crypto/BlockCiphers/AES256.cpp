//
// Created by neodar on 07/04/2020.
//

#include "AES256.h"

std::string HCL::Crypto::AES256::GetHeader() {
  return GetIdBytes() + key_stretching_->GetHeader();
}
