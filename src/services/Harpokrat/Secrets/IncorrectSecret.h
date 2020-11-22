//
// Created by neodar on 22/11/2020.
//

#ifndef HCL_SRC_SERVICES_HARPOKRAT_SECRETS_INCORRECTSECRET_H_
#define HCL_SRC_SERVICES_HARPOKRAT_SECRETS_INCORRECTSECRET_H_

#include "ASecret.h"

namespace HCL {
class IncorrectSecret : public ASecret {
 public:
  IncorrectSecret() : ASecret() {};
  ~IncorrectSecret() override = default;
  [[nodiscard]] bool CorrectDecryption() const override;

 protected:
  [[nodiscard]] SecretType GetSecretType() const override {
    return INCORRECT;
  };
  [[nodiscard]] std::string SerializeContent() const override;
  bool DeserializeContent(const std::string &content) override;
};
}

#endif //HCL_SRC_SERVICES_HARPOKRAT_SECRETS_INCORRECTSECRET_H_
