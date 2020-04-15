//
// Created by neodar on 07/04/2020.
//

#include "HMAC.h"
#include "../CryptoHelper.h"

HCL::Crypto::HMAC::HMAC(const std::string &header, size_t &header_length) {
  hash_function_ = Factory<AHashFunction>::BuildTypedFromHeader(header, header_length);
}

std::string HCL::Crypto::HMAC::SignMessage(const std::string &key, const std::string &message) {
  if (!hash_function_) {
    throw std::runtime_error(GetDependencyUnsetError("sign message", "Hash function"));
  }
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

std::string HCL::Crypto::HMAC::GetHeader() {
  if (!hash_function_) {
    throw std::runtime_error(GetDependencyUnsetError("get header", "Hash function"));
  }
  return GetIdBytes() + hash_function_->GetHeader();
}

void HCL::Crypto::HMAC::SetHashFunction(std::unique_ptr<ACryptoElement> hash_function) {
  hash_function_ = ACryptoElement::UniqueTo<AHashFunction>(std::move(hash_function));
}

bool HCL::Crypto::HMAC::IsHashFunctionSet() const {
  return !!hash_function_;
}

HCL::Crypto::ACryptoElement &HCL::Crypto::HMAC::GetHashFunction() const {
  if (!IsHashFunctionSet()) {
    throw std::runtime_error(GetDependencyUnsetError("get Hash function", "Hash function"));
  }
  return *hash_function_;
}
