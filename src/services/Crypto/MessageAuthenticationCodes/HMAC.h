//
// Created by neodar on 07/04/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_MESSAGEAUTHENTICATIONCODES_HMAC_H_
#define HCL_SRC_SERVICES_CRYPTO_MESSAGEAUTHENTICATIONCODES_HMAC_H_

#include "../AutoRegisterer.h"
#include "AMessageAuthenticationCode.h"
#include "../HashFunctions/AHashFunction.h"

namespace HCL::Crypto {

// TODO Optimize everything

class HMAC : public AutoRegisterer<AMessageAuthenticationCode, HMAC> {
 public:
  HMAC() = default;
  HMAC(const std::string &header, size_t &header_length);
  const std::vector<std::string> &GetRequiredDependencies() override {
    static const std::vector<std::string> dependencies(
        {
            AHashFunction::GetName(),
        });
    return dependencies;
  }
  void SetDependency(std::unique_ptr<ACryptoElement> dependency, size_t index) override {
    if (index >= 1) {
      throw std::runtime_error("HMAC error: Cannot set dependency: Incorrect dependency index");
    }
    switch (index) {
      case 0:
      default:
        SetHashFunction(std::move(dependency));
    }
  }
  std::string SignMessage(const std::string &key, const std::string &message);
  std::string GetHeader() override;
  void SetHashFunction(std::unique_ptr<ACryptoElement> hash_function);
  const std::string &GetElementName() override { return GetName(); };
  const std::string &GetElementTypeName() override { return GetTypeName(); };
  static const uint16_t id = 1;
  static const std::string &GetName() {
    static std::string name = "hmac";
    return name;
  };
 private:
  std::unique_ptr<AHashFunction> hash_function_;
};
}

#endif //HCL_SRC_SERVICES_CRYPTO_MESSAGEAUTHENTICATIONCODES_HMAC_H_
