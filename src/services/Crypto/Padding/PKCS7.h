//
// Created by neodar on 07/04/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_PADDING_PKCS7_H_
#define HCL_SRC_SERVICES_CRYPTO_PADDING_PKCS7_H_

#include "../AutoRegisterer.h"
#include "APadding.h"
namespace HCL::Crypto {

class PKCS7 : public AutoRegisterer<APadding, PKCS7> {
 public:
  PKCS7(const std::string &header, size_t &header_length) {
    is_registered_;
  };
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
  std::string PadDataToSize(const std::string &data, size_t size) override;
  std::string RemovePadding(const std::string &data) override;
  std::string GetHeader() override;
  static const uint16_t id = 1;
  static const std::string &GetName() {
    static std::string name = "pkcs7";
    return name;
  };
};
}

#endif //HCL_SRC_SERVICES_CRYPTO_PADDING_PKCS7_H_
