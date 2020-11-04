//
// Created by neodar on 06/04/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_BLOCKCIPHERMODES_ECB_H_
#define HCL_SRC_SERVICES_CRYPTO_BLOCKCIPHERMODES_ECB_H_

#include "ABlockCipherMode.h"
#include "../AutoRegisterer.h"
#include "../Padding/APaddedCipher.h"

namespace HCL::Crypto {

class ECB : public AutoRegisterer<ABlockCipherMode, ECB>,
            public APaddedCipher {
 public:
  ECB() = default;
  ECB(const std::string &header, size_t &header_length);
  const std::vector<std::string> &GetDependenciesTypes() override {
    static const std::vector<std::string> dependencies(
        {
            ABlockCipher::GetName(),
            APadding::GetName(),
        });
    return dependencies;
  }
  void SetDependency(std::unique_ptr<ACryptoElement> dependency, size_t index) override {
    if (index >= 3) {
      throw std::runtime_error(AutoRegisterer::GetDependencyIndexError("set"));
    }
    switch (index) {
      case 0:SetCipher(std::move(dependency));
        break;
      case 1:
      default:SetPadding(std::move(dependency));
    }
  }
  bool IsDependencySet(size_t index) override {
    if (index >= 3) {
      throw std::runtime_error(AutoRegisterer::GetDependencyIndexError("check"));
    }
    switch (index) {
      case 0:return IsCipherSet();
      case 1:
      default:return IsPaddingSet();;
    }
  }
  ACryptoElement &GetDependency(size_t index) override {
    if (index >= 3) {
      throw std::runtime_error(AutoRegisterer::GetDependencyIndexError("get"));
    }
    switch (index) {
      case 0:return GetCipher();
      case 1:
      default:return GetPadding();
    }
  }
  std::string Encrypt(const std::string &key, const std::string &content) override;
  std::string Decrypt(const std::string &key, const std::string &content) override;
  const std::string &GetElementName() const override { return GetName(); };
  const std::string &GetElementTypeName() const override { return GetTypeName(); };
  static const uint16_t id = 2;
  static const std::string &GetName() {
    static std::string name = "ecb";
    return name;
  };
  std::string GetHeader() override;
};
}

#endif //HCL_SRC_SERVICES_CRYPTO_BLOCKCIPHERMODES_ECB_H_
