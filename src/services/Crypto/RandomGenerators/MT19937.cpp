//
// Created by neodar on 07/04/2020.
//

#include "MT19937.h"

HCL::Crypto::MT19937::MT19937():
    generator_(random_device_()),
    distribution_(0, 255) {
}

HCL::Crypto::MT19937::MT19937(const std::string &header, size_t &header_length) : MT19937() {}

uint8_t HCL::Crypto::MT19937::GenerateRandomByte() {
  return distribution_(generator_);
}

std::string HCL::Crypto::MT19937::GenerateRandomByteSequence(size_t sequence_length) {
  std::string sequence;

  for (size_t i = 0; i < sequence_length; ++i) {
    sequence += (char) GenerateRandomByte();
  }

  return sequence;
}

HCL::Crypto::BigNumber HCL::Crypto::MT19937::GenerateRandomBigNumber(size_t bits) {
  BigNumber random_number;

  while (bits >= sizeof(uint8_t) * 8) {
    random_number <<= sizeof(uint8_t) * 8;
    random_number += GenerateRandomByte();
    bits -= sizeof(uint8_t) * 8;
  }
  if (bits > 0) {
    random_number <<= bits;
    random_number += GenerateRandomByte() >> (sizeof(uint8_t) * 8 - bits);
  }
  return random_number;
}

std::string HCL::Crypto::MT19937::GetHeader() {
  return GetIdBytes();
}
