//
// Created by neodar on 07/04/2020.
//

#include "AInitializationVectorBlockCipherMode.h"
#include "../Factory.h"

HCL::Crypto::AInitializationVectorBlockCipherMode::AInitializationVectorBlockCipherMode(
    const std::string &header,
    size_t &header_length
) {
  this->random_generator_ = Factory<ARandomGenerator>::BuildTypedFromHeader(header, header_length);
}

std::string HCL::Crypto::AInitializationVectorBlockCipherMode::GetInitializationVector(
    size_t initialization_vector_length
) {
  if (!random_generator_) {
    throw std::runtime_error(GetDependencyUnsetError("get initialization vector", "Random generator"));
  }
  return random_generator_->GenerateRandomByteSequence(initialization_vector_length);
}

std::string HCL::Crypto::AInitializationVectorBlockCipherMode::GetHeader() {
  if (!random_generator_) {
    throw std::runtime_error(GetDependencyUnsetError("get header", "Random generator"));
  }
  return random_generator_->GetHeader();
}

void HCL::Crypto::AInitializationVectorBlockCipherMode::SetRandomGenerator(
    std::unique_ptr<ACryptoElement> random_generator) {
  random_generator_ = ACryptoElement::UniqueTo<ARandomGenerator>(std::move(random_generator));
}

bool HCL::Crypto::AInitializationVectorBlockCipherMode::IsRandomGeneratorSet() const {
  return !!random_generator_;
}

HCL::Crypto::ACryptoElement &HCL::Crypto::AInitializationVectorBlockCipherMode::GetRandomGenerator() const {
  if (!IsRandomGeneratorSet()) {
    throw std::runtime_error(GetDependencyUnsetError("get Random generator", "Random generator"));
  }

  return *random_generator_;
}
