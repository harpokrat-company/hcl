//
// Created by antoine on 20/07/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_ASYMMETRICCIPHERS_AASYMMETRICCIPHER_H_
#define HCL_SRC_SERVICES_CRYPTO_ASYMMETRICCIPHERS_AASYMMETRICCIPHER_H_

#include <gmpxx.h>

#include "../ACryptoElement.h"
#include "KeyPair.h"

namespace HCL::Crypto {
class AAsymmetricCipher : public ACryptoElement {
 public:
  virtual ~AAsymmetricCipher() = default;
  virtual KeyPair *GenerateKeyPair(size_t bits) = 0;
  virtual std::string Encrypt(const mpz_class &modulus, const mpz_class &public_key, const std::string &content) = 0;
  virtual std::string Decrypt(const mpz_class &modulus, const mpz_class &private_key, const std::string &content) = 0;
  virtual std::string GetHeader() = 0;
  static const std::string &GetName() {
    static std::string name = "asymmetric-cipher";
    return name;
  };
 private:
};
}

#endif //HCL_SRC_SERVICES_CRYPTO_ASYMMETRICCIPHERS_AASYMMETRICCIPHER_H_
