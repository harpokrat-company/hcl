//
// Created by neodar on 07/04/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_RANDOMGENERATORS_ARANDOMGENERATOR_H_
#define HCL_SRC_SERVICES_CRYPTO_RANDOMGENERATORS_ARANDOMGENERATOR_H_

#include <cstdint>
#include <string>
#include "../ACryptoElement.h"

namespace HCL::Crypto {

class ARandomGenerator : public ACryptoElement {
 public:
  virtual uint8_t GenerateRandomByte() = 0;
  virtual std::string GenerateRandomByteSequence(size_t sequence_length) = 0;
  virtual std::string GetHeader() = 0;
  static const std::string &GetName() {
    static std::string name = "random-generator";
    return name;
  };
};
}

#endif //HCL_SRC_SERVICES_CRYPTO_RANDOMGENERATORS_ARANDOMGENERATOR_H_
