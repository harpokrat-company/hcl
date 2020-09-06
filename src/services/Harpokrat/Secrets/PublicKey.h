//
// Created by neodar on 06/09/2020.
//

#ifndef HCL_SRC_SERVICES_HARPOKRAT_SECRETS_PUBLICKEY_H_
#define HCL_SRC_SERVICES_HARPOKRAT_SECRETS_PUBLICKEY_H_

#include <gmpxx.h>
#include "ASecret.h"

namespace HCL {
union SerializedPublicKeyHeader {
  uint16_t fields_sizes[3];
  char bytes[6];
};

class PublicKey : public ASecret {
 public:
  PublicKey() : ASecret() {};
  PublicKey(mpz_class modulus, mpz_class public_key);
  std::string Encrypt(const std::string &message);

 protected:
  [[nodiscard]] SecretType GetSecretType() const override {
    return PUBLIC_KEY;
  };
  [[nodiscard]] std::string SerializeContent(const std::string &key) const override;
  bool DeserializeContent(const std::string &content) override;

 public:
  std::string owner_;
  mpz_class modulus_;
  mpz_class public_key_;
};
}

#endif //HCL_SRC_SERVICES_HARPOKRAT_SECRETS_PUBLICKEY_H_
