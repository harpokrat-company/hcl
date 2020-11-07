//
// Created by neodar on 05/11/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_RSAKey_H_
#define HCL_SRC_SERVICES_CRYPTO_RSAKey_H_

#include <gmpxx.h>

namespace HCL::Crypto {
class RSAKey {
 public:
  RSAKey(mpz_class modulus, mpz_class key);
  ~RSAKey() = default;
  [[nodiscard]] mpz_class GetModulus() const;
  [[nodiscard]] mpz_class GetKey() const;

 private:
  mpz_class modulus_;
  mpz_class key_;
};
}

#endif //HCL_SRC_SERVICES_CRYPTO_RSAKey_H_
