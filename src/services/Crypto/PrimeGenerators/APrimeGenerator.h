//
// Created by antoine on 10/06/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_PRIMEGENERATORS_APRIMEGENERATOR_H_
#define HCL_SRC_SERVICES_CRYPTO_PRIMEGENERATORS_APRIMEGENERATOR_H_

#include <cstdint>
#include <string>
#include <gmp.h>
#include "../ACryptoElement.h"

namespace HCL::Crypto {

class APrimeGenerator : public ACryptoElement {
 public:
  virtual ~APrimeGenerator() = default;
  virtual std::string GetHeader() = 0;
  virtual __mpz_struct GenerateRandomPrime(size_t bits) = 0;
  static const std::string &GetName() {
    static std::string name = "prime-generator";
    return name;
  };
};
}

#endif //HCL_SRC_SERVICES_CRYPTO_PRIMEGENERATORS_APRIMEGENERATOR_H_
