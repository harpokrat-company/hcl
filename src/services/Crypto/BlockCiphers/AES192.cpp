//
// Created by neodar on 07/04/2020.
//

#include "AES192.h"

std::string HCL::Crypto::AES192::GetHeader() {
  if (!key_stretching_function_) {
    throw std::runtime_error("AES192 error: Key stretching function is not set");
  }
  return GetIdBytes() + key_stretching_function_->GetHeader();
}
