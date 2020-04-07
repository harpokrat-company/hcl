//
// Created by neodar on 07/04/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_RANDOMGENERATORS_MT19937GENERATOR_H_
#define HCL_SRC_SERVICES_CRYPTO_RANDOMGENERATORS_MT19937GENERATOR_H_

#include <random>
#include "../AutoRegisterer.h"
#include "ARandomGenerator.h"

namespace HCL::Crypto {

class MT19937Generator : AutoRegisterer<ARandomGenerator, MT19937Generator> {
 public:
  MT19937Generator(const std::string &header, size_t &header_length);
  uint8_t GenerateRandomByte() override;
  std::string GenerateRandomByteSequence(size_t sequence_length) override;
  std::string GetHeader() override;
  static const uint16_t id = 1;
  static const std::string name;
 private:
  std::random_device random_device_;
  std::mt19937 generator_;
  std::uniform_int_distribution<uint8_t> distribution_;
};
}

#endif //HCL_SRC_SERVICES_CRYPTO_RANDOMGENERATORS_MT19937GENERATOR_H_
