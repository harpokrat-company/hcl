//
// Created by neodar on 07/04/2020.
//

#include "HMAC.h"
#include "../CryptoHelper.h"

HCL::Crypto::HMAC::HMAC(const std::string &header, size_t &header_length) {
  is_registered_;
  hash_function_ = Factory<AHashFunction>::GetInstanceFromHeader(header, header_length);
}

std::string HCL::Crypto::HMAC::SignMessage(const std::string &key, const std::string &message) {
  std::string prepared_key = key;
  size_t bloc_size = hash_function_->GetBlocSize();
  std::string outer_key;
  std::string inner_key;

  if (prepared_key.length() > bloc_size) {
    prepared_key = hash_function_->HashData(prepared_key);
  }
  if (prepared_key.length() < bloc_size) {
    prepared_key += std::string(bloc_size - prepared_key.length(), (char) 0x00);
  }
  outer_key = CryptoHelper::XorStrings(prepared_key, std::string(bloc_size, 0x5c));
  inner_key = CryptoHelper::XorStrings(prepared_key, std::string(bloc_size, 0x36));
  return hash_function_->HashData(outer_key + hash_function_->HashData(inner_key + message));
}
