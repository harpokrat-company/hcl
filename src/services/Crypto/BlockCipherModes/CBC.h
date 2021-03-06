//
// Created by neodar on 06/04/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_BLOCKCIPHERMODES_CBC_H_
#define HCL_SRC_SERVICES_CRYPTO_BLOCKCIPHERMODES_CBC_H_

#include <stdexcept>
#include "ABlockCipherMode.h"
#include "../AutoRegisterer.h"
#include "../Padding/APaddedCipher.h"
#include "AInitializationVectorBlockCipherMode.h"

namespace HCL::Crypto {

class CBC : public AutoRegisterer<ABlockCipherMode, CBC>,
            public APaddedCipher,
            public AInitializationVectorBlockCipherMode {
 public:
  CBC() = default;
  CBC(const std::string &header, size_t &header_length);
  const std::vector<std::string> &GetDependenciesTypes() override {
    static const std::vector<std::string> dependencies(
        {
            ABlockCipher::GetName(),
            APadding::GetName(),
            ARandomGenerator::GetName(),
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
      case 1:SetPadding(std::move(dependency));
        break;
      case 2:
      default:SetRandomGenerator(std::move(dependency));
    }
  }
  bool IsDependencySet(size_t index) override {
    if (index >= 3) {
      throw std::runtime_error(AutoRegisterer::GetDependencyIndexError("check"));
    }
    switch (index) {
      case 0:return IsCipherSet();
      case 1:return IsPaddingSet();
      case 2:
      default:return IsRandomGeneratorSet();
    }
  }
  ACryptoElement &GetDependency(size_t index) override {
    if (index >= 3) {
      throw std::runtime_error(AutoRegisterer::GetDependencyIndexError("get"));
    }
    switch (index) {
      case 0:return GetCipher();
      case 1:return GetPadding();
      case 2:
      default:return GetRandomGenerator();
    }
  }
  std::string Encrypt(const std::string &key, const std::string &content) override;
  std::string Decrypt(const std::string &key, const std::string &content) override;
  const std::string &GetElementName() const override { return GetName(); };
  const std::string &GetElementTypeName() const override { return GetTypeName(); };
  static const uint16_t id = 1;
  static const std::string &GetName() {
    static std::string name = "cbc";
    return name;
  };
  std::string GetHeader() override;
};
}

#endif //HCL_SRC_SERVICES_CRYPTO_BLOCKCIPHERMODES_CBC_H_
