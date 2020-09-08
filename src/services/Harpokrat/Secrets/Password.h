//
// Created by neodar on 06/09/2020.
//

#ifndef HCL_SRC_SERVICES_HARPOKRAT_SECRETS_PASSWORD_H_
#define HCL_SRC_SERVICES_HARPOKRAT_SECRETS_PASSWORD_H_

#include "ASecret.h"

namespace HCL {
union SerializedPasswordHeader {
  uint16_t fields_sizes[4];
  char bytes[8];
};

class Password : public ASecret {
 public:
  Password() : ASecret() {};
  ~Password() override = default;
  [[nodiscard]] const std::string &GetName() const;
  [[nodiscard]] const std::string &GetLogin() const;
  [[nodiscard]] const std::string &GetPassword() const;
  [[nodiscard]] const std::string &GetDomain() const;
  void SetName(const std::string &);
  void SetLogin(const std::string &);
  void SetPassword(const std::string &);
  void SetDomain(const std::string &);

 protected:
  [[nodiscard]] SecretType GetSecretType() const override {
    return PASSWORD;
  };
  [[nodiscard]] std::string SerializeContent() const override;
  bool DeserializeContent(const std::string &content) override;

 private:
  std::string name_;
  std::string login_;
  std::string password_;
  std::string domain_;
};
}

#endif //HCL_SRC_SERVICES_HARPOKRAT_SECRETS_PASSWORD_H_
