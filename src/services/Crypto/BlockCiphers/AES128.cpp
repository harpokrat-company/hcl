//
// Created by neodar on 07/04/2020.
//

#include "AES128.h"

std::string HCL::Crypto::AES128::GetHeader() {
  return GetIdBytes() + key_stretching_function_->GetHeader();
}
