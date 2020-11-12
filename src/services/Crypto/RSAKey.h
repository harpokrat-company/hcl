//
// Created by neodar on 05/11/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_RSAKey_H_
#define HCL_SRC_SERVICES_CRYPTO_RSAKey_H_

#include <gmp.h>
#include <string>

namespace HCL::Crypto {
class RSAKey {
 public:
  RSAKey(__mpz_struct modulus, __mpz_struct key);
  ~RSAKey() = default;
  [[nodiscard]] __mpz_struct GetModulus() const;
  [[nodiscard]] __mpz_struct GetKey() const;

 private:
  std::string owner_;
  __mpz_struct modulus_;
  __mpz_struct key_;
};
}

#endif //HCL_SRC_SERVICES_CRYPTO_RSAKey_H_
