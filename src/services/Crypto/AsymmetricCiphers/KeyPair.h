//
// Created by antoine on 28/08/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_ASYMMETRICCIPHERS_KEYPAIR_H_
#define HCL_SRC_SERVICES_CRYPTO_ASYMMETRICCIPHERS_KEYPAIR_H_

#include <utility>
#include "../../Harpokrat/Secrets/PrivateKey.h"
#include "../../Harpokrat/Secrets/PublicKey.h"

namespace HCL::Crypto {
class KeyPair {
 public:
  KeyPair(__mpz_struct public_key, __mpz_struct private_key, __mpz_struct modulus);
  [[nodiscard]] PublicKey *GetPublic() const;
  [[nodiscard]] PrivateKey *GetPrivate() const;
 private:
  __mpz_struct modulus_;
  __mpz_struct public_key_;
  __mpz_struct private_key_;
};
}

#endif //HCL_SRC_SERVICES_CRYPTO_ASYMMETRICCIPHERS_KEYPAIR_H_
