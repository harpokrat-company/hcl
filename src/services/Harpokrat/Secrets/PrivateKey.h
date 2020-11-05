//
// Created by neodar on 06/09/2020.
//

#ifndef HCL_SRC_SERVICES_HARPOKRAT_SECRETS_PRIVATEKEY_H_
#define HCL_SRC_SERVICES_HARPOKRAT_SECRETS_PRIVATEKEY_H_

#include <gmpxx.h>
#include "ASecret.h"
#include "../../Crypto/Ciphers/ICipherDecryptionKey.h"
#include "../../Crypto/RSAKey.h"

namespace HCL {
union SerializedPrivateKeyHeader {
  uint16_t fields_sizes[3];
  char bytes[6];
};

class PrivateKey : public ASecret, public Crypto::ICipherDecryptionKey {
 public:
  PrivateKey() : ASecret() {};
  PrivateKey(mpz_class modulus, mpz_class private_key);
  PrivateKey(const Crypto::RSAKey &);
  ~PrivateKey() override = default;
  [[nodiscard]] std::string Decrypt(const std::string &encrypted) const;
  [[nodiscard]] const std::string &GetOwner() const;
  void SetOwner(const std::string &owner);
  [[nodiscard]] const std::string &GetDecryptionKeyType() const override {
    static std::string key_type = "private";
    return key_type;
  }
  [[nodiscard]] Crypto::RSAKey ExtractKey() const;

 protected:
  [[nodiscard]] SecretType GetSecretType() const override {
    return PRIVATE_KEY;
  };
  [[nodiscard]] std::string SerializeContent() const override;
  bool DeserializeContent(const std::string &content) override;

 private:
  std::string owner_;
  mpz_class modulus_;
  mpz_class private_key_;
};
}

#endif //HCL_SRC_SERVICES_HARPOKRAT_SECRETS_PRIVATEKEY_H_
