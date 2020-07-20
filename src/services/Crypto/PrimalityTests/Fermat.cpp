//
// Created by antoine on 10/06/2020.
//

#include "Fermat.h"

HCL::Crypto::Fermat::Fermat() {
}

HCL::Crypto::Fermat::Fermat(const std::string &header, size_t &header_length) : Fermat() {}

bool HCL::Crypto::Fermat::IsPrime(BigNumber number) {
//  if (!random_generator_) {
//	throw std::runtime_error(GetDependencyUnsetError("is prime", "Random generator"));
//  }
//TODO: Set the random BigNumber to a real random BigNumber lower than the number given as Input using the dependency
  BigNumber random;

  random = 2;
  return random.ModularExponentiation(number - 1, number) == 1;
}

std::string HCL::Crypto::Fermat::GetHeader() {
  if (!random_generator_) {
	throw std::runtime_error(GetDependencyUnsetError("get header", "Random generator"));
  }
  return GetIdBytes() + random_generator_->GetHeader();
}

void HCL::Crypto::Fermat::SetRandomGenerator(std::unique_ptr<ACryptoElement> hash_function) {
  random_generator_ = ACryptoElement::UniqueTo<ARandomGenerator>(std::move(hash_function));
}

bool HCL::Crypto::Fermat::IsRandomGeneratorSet() const {
  return !!random_generator_;
}

HCL::Crypto::ACryptoElement &HCL::Crypto::Fermat::GetRandomGenerator() const {
  if (!IsRandomGeneratorSet()) {
	throw std::runtime_error(GetDependencyUnsetError("get Random generator", "Random generator"));
  }
  return *random_generator_;
}