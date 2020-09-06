//
// Created by neodar on 06/09/2020.
//

#ifndef HCL_SRC_SERVICES_HARPOKRAT_SECRETS_PRIVATEKEY_H_
#define HCL_SRC_SERVICES_HARPOKRAT_SECRETS_PRIVATEKEY_H_

#include <gmpxx.h>
#include "ASecret.h"

namespace HCL {
union SerializedPrivateKeyHeader {
  uint16_t fields_sizes[3];
  char bytes[6];
};

class PrivateKey : public ASecret {
 public:
  PrivateKey() : ASecret() {};
  PrivateKey(mpz_class modulus, mpz_class private_key);
  std::string Decrypt(const std::string &encrypted);
  [[nodiscard]] const std::string &GetOwner() const;
  void SetOwner(const std::string &owner);

 protected:
  [[nodiscard]] SecretType GetSecretType() const override {
    return PRIVATE_KEY;
  };
  [[nodiscard]] std::string SerializeContent(const std::string &key) const override;
  bool DeserializeContent(const std::string &content) override;

 private:
  std::string owner_;
  mpz_class modulus_;
  mpz_class private_key_;
};
}

#endif //HCL_SRC_SERVICES_HARPOKRAT_SECRETS_PRIVATEKEY_H_
