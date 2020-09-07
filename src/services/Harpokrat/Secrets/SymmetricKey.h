//
// Created by neodar on 07/09/2020.
//

#ifndef HCL_SRC_SERVICES_HARPOKRAT_SECRETS_SYMMETRICKEY_H_
#define HCL_SRC_SERVICES_HARPOKRAT_SECRETS_SYMMETRICKEY_H_

#include "ASecret.h"

namespace HCL {
union SerializedSymmetricKeyHeader {
  uint16_t fields_sizes[2];
  char bytes[4];
};

class SymmetricKey : public ASecret {
 public:
  SymmetricKey() : ASecret() {};
  [[nodiscard]] const std::string &GetOwner() const;
  void SetOwner(const std::string &owner);
  [[nodiscard]] const std::string &GetKey() const;
  void SetKey(const std::string &key);

 protected:
  [[nodiscard]] SecretType GetSecretType() const override {
    return PUBLIC_KEY;
  };
  [[nodiscard]] std::string SerializeContent(const std::string &key) const override;
  bool DeserializeContent(const std::string &content) override;

 public:
  std::string owner_;
  std::string key_;
};
}

#endif //HCL_SRC_SERVICES_HARPOKRAT_SECRETS_SYMMETRICKEY_H_
