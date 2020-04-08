//
// Created by neodar on 07/04/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_MESSAGEAUTHENTICATIONCODES_HMAC_H_
#define HCL_SRC_SERVICES_CRYPTO_MESSAGEAUTHENTICATIONCODES_HMAC_H_

#include "../AutoRegisterer.h"
#include "AMessageAuthenticationCode.h"
#include "../HashFunctions/AHashFunction.h"

namespace HCL::Crypto {

class HMAC : public AutoRegisterer<AMessageAuthenticationCode, HMAC> {
 public:
  HMAC(const std::string &header, size_t &header_length);
  const std::vector<std::string> &GetDependencies() override {
    static const std::vector<std::string> dependencies({"Aled", "Oskour"});
    // TODO
    return dependencies;
  }
  const std::map<size_t, void (*)(std::unique_ptr<AutoRegistrable>)> &GetDependencySetters() override {
    static const std::map<size_t, void (*)(std::unique_ptr<AutoRegistrable>)> dependency_setters = {
        {0, nullptr},
    };
    // TODO
    return dependency_setters;
  }
  std::string SignMessage(const std::string &key, const std::string &message);
  std::string GetHeader() override;
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
