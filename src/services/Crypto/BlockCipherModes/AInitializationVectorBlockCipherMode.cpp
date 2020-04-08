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
  return random_generator_->GenerateRandomByteSequence(initialization_vector_length);
}

std::string HCL::Crypto::AInitializationVectorBlockCipherMode::GetHeader() {
  return random_generator_->GetHeader();
}
