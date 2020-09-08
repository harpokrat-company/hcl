//
// Created by neodar on 07/09/2020.
//

#ifndef HCL_SRC_SERVICES_HARPOKRAT_SECRETS_SYMMETRICKEY_H_
#define HCL_SRC_SERVICES_HARPOKRAT_SECRETS_SYMMETRICKEY_H_

#include "ASecret.h"
#include "../../Crypto/Ciphers/ICipherEncryptionKey.h"
#include "../../Crypto/Ciphers/ICipherDecryptionKey.h"

namespace HCL {
union SerializedSymmetricKeyHeader {
  uint16_t fields_sizes[2];
  char bytes[4];
};

class SymmetricKey : public ASecret, public Crypto::ICipherEncryptionKey, public Crypto::ICipherDecryptionKey {
 public:
  SymmetricKey() : ASecret() {};
  ~SymmetricKey() override = default;
  [[nodiscard]] const std::string &GetOwner() const;
  void SetOwner(const std::string &owner);
  [[nodiscard]] const std::string &GetKey() const;
  void SetKey(const std::string &key);
  [[nodiscard]] const std::string &GetEncryptionKeyType() const override {
    static std::string key_type = "symmetric";
    return key_type;
  }
  [[nodiscard]] const std::string &GetDecryptionKeyType() const override {
    static std::string key_type = "symmetric";
    return key_type;
  }

 protected:
  [[nodiscard]] SecretType GetSecretType() const override {
    return PUBLIC_KEY;
  };
  [[nodiscard]] std::string SerializeContent() const override;
  bool DeserializeContent(const std::string &content) override;

 public:
  std::string owner_;
  std::string key_;
};
}

#endif //HCL_SRC_SERVICES_HARPOKRAT_SECRETS_SYMMETRICKEY_H_
