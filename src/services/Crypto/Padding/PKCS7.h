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
  PKCS7() = default;
  PKCS7(const std::string &header, size_t &header_length) {};
  const std::vector<std::string> &GetDependenciesTypes() override {
    static const std::vector<std::string> dependencies({});
    return dependencies;
  }
  void SetDependency(std::unique_ptr<ACryptoElement> dependency, size_t index) override {
    throw std::runtime_error(GetDependencyIndexError("set"));
  }
  bool IsDependencySet(size_t index) override {
    throw std::runtime_error(GetDependencyIndexError("check"));
  }
  ACryptoElement &GetDependency(size_t index) override {
    throw std::runtime_error(GetDependencyIndexError("get"));
  }
  std::string PadDataToSize(const std::string &data, size_t size) override;
  std::string RemovePadding(const std::string &data) override;
  std::string GetHeader() override;
  const std::string &GetElementName() const override { return GetName(); };
  const std::string &GetElementTypeName() const override { return GetTypeName(); };
  static const uint16_t id = 1;
  static const std::string &GetName() {
    static std::string name = "pkcs7";
    return name;
  };
};
}

#endif //HCL_SRC_SERVICES_CRYPTO_PADDING_PKCS7_H_
