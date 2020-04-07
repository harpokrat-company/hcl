//
// Created by neodar on 07/04/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_RANDOMGENERATORS_ARANDOMGENERATOR_H_
#define HCL_SRC_SERVICES_CRYPTO_RANDOMGENERATORS_ARANDOMGENERATOR_H_

#include <cstdint>
#include <string>

namespace HCL::Crypto {

class ARandomGenerator {
 public:
  virtual uint8_t GenerateRandomByte() = 0;
  virtual std::string GenerateRandomByteSequence(size_t sequence_length) = 0;
};
}

#endif //HCL_SRC_SERVICES_CRYPTO_RANDOMGENERATORS_ARANDOMGENERATOR_H_
