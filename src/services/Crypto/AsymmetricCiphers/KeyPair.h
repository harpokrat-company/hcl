//
// Created by antoine on 28/08/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_ASYMMETRICCIPHERS_KEYPAIR_H_
#define HCL_SRC_SERVICES_CRYPTO_ASYMMETRICCIPHERS_KEYPAIR_H_

#include <gmpxx.h>
#include <utility>
#include "../../Harpokrat/Secrets/PrivateKey.h"
#include "../../Harpokrat/Secrets/PublicKey.h"

namespace HCL::Crypto {
class KeyPair {
 public:
  KeyPair(mpz_class public_key, mpz_class private_key, mpz_class modulus);
  [[nodiscard]] PublicKey GetPublic() const;
  [[nodiscard]] PrivateKey GetPrivate() const;
 private:
  mpz_class modulus_;
  mpz_class public_key_;
  mpz_class private_key_;
};
}

#endif //HCL_SRC_SERVICES_CRYPTO_ASYMMETRICCIPHERS_KEYPAIR_H_
