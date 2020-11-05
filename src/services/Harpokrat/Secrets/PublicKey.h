//
// Created by neodar on 06/09/2020.
//

#ifndef HCL_SRC_SERVICES_HARPOKRAT_SECRETS_PUBLICKEY_H_
#define HCL_SRC_SERVICES_HARPOKRAT_SECRETS_PUBLICKEY_H_

#include <gmpxx.h>
#include "ASecret.h"
#include "../../Crypto/Ciphers/ICipherEncryptionKey.h"
#include "../../Crypto/RSAKey.h"

namespace HCL {
union SerializedPublicKeyHeader {
  uint16_t fields_sizes[3];
  char bytes[6];
};

class PublicKey : public ASecret, public Crypto::ICipherEncryptionKey {
 public:
  PublicKey() : ASecret() {};
  PublicKey(mpz_class modulus, mpz_class public_key);
  PublicKey(const Crypto::RSAKey &);
  ~PublicKey() override = default;
  [[nodiscard]] std::string Encrypt(const std::string &message) const;
  [[nodiscard]] const std::string &GetOwner() const;
  void SetOwner(const std::string &owner);
  [[nodiscard]] const std::string &GetEncryptionKeyType() const override {
    static std::string key_type = "public";
    return key_type;
  }
  [[nodiscard]] Crypto::RSAKey ExtractKey() const;

 protected:
  [[nodiscard]] SecretType GetSecretType() const override {
    return PUBLIC_KEY;
  };
  [[nodiscard]] std::string SerializeContent() const override;
  bool DeserializeContent(const std::string &content) override;

 public:
  std::string owner_;
  mpz_class modulus_;
  mpz_class public_key_;
};
}

#endif //HCL_SRC_SERVICES_HARPOKRAT_SECRETS_PUBLICKEY_H_
