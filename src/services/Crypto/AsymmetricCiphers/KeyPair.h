//
// Created by antoine on 28/08/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_ASYMMETRICCIPHERS_KEYPAIR_H_
#define HCL_SRC_SERVICES_CRYPTO_ASYMMETRICCIPHERS_KEYPAIR_H_

#include <gmpxx.h>
#include <utility>
class KeyPair {
 public:
  KeyPair(const mpz_class &public_key, const mpz_class &private_key, const mpz_class &modulus);
  const std::pair<mpz_class, mpz_class> &GetPublic();
  const std::pair<mpz_class, mpz_class> &GetPrivate();
 private:
  std::pair<mpz_class, mpz_class> public_key;
  std::pair<mpz_class, mpz_class> private_key;
};

#endif //HCL_SRC_SERVICES_CRYPTO_ASYMMETRICCIPHERS_KEYPAIR_H_
