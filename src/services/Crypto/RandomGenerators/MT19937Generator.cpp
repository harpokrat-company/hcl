//
// Created by neodar on 07/04/2020.
//

#include "MT19937Generator.h"

const std::string HCL::Crypto::MT19937Generator::name = "mt19937-generator";

HCL::Crypto::MT19937Generator::MT19937Generator(const std::string &header, size_t &header_length) :
  generator_(random_device_()),
  distribution_(0, 255) {
}

uint8_t HCL::Crypto::MT19937Generator::GenerateRandomByte() {
  return distribution_(generator_);
}

std::string HCL::Crypto::MT19937Generator::GenerateRandomByteSequence(size_t sequence_length) {
  std::string sequence;

  for (size_t i = 0; i < sequence_length; ++i) {
    sequence += (char) GenerateRandomByte();
  }

  return sequence;
}
std::string HCL::Crypto::MT19937Generator::GetHeader() {
  return GetIdBytes();
}
