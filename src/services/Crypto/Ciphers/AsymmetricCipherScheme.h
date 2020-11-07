//
// Created by neodar on 07/09/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_CIPHERS_ASYMMETRICCIPHERSCHEME_H_
#define HCL_SRC_SERVICES_CRYPTO_CIPHERS_ASYMMETRICCIPHERSCHEME_H_

#include <stdexcept>
#include "ACipher.h"
#include "../AutoRegisterer.h"
#include "../AsymmetricCiphers/AAsymmetricCipher.h"

namespace HCL::Crypto {

class AsymmetricCipherScheme : public AutoRegisterer<ACipher, AsymmetricCipherScheme>  {
 public:
  AsymmetricCipherScheme() = default;
  AsymmetricCipherScheme(const std::string &header, size_t &header_length);
  const std::vector<std::string> &GetDependenciesTypes() override {
    static const std::vector<std::string> dependencies(
        {
            AAsymmetricCipher::GetName(),
        });
    return dependencies;
  }
  void SetDependency(std::unique_ptr<ACryptoElement> dependency, size_t index) override {
    if (index >= 1) {
      throw std::runtime_error(GetDependencyIndexError("set"));
    }
    switch (index) {
      case 0:
      default:SetAsymmetricCipher(std::move(dependency));
    }
  }
  bool IsDependencySet(size_t index) override {
    if (index >= 1) {
      throw std::runtime_error(GetDependencyIndexError("check"));
    }
    switch (index) {
      case 0:
      default:return IsAsymmetricCipherSet();
    }
  }
  ACryptoElement &GetDependency(size_t index) override {
    if (index >= 1) {
      throw std::runtime_error(GetDependencyIndexError("get"));
    }
    switch (index) {
      case 0:
      default:return GetAsymmetricCipher();
    }
  }
  std::string Encrypt(const ICipherEncryptionKey *key, const std::string &content) override;
  std::string Decrypt(const ICipherDecryptionKey *key, const std::string &content) override;
  std::string GetHeader() override;
  void SetAsymmetricCipher(std::unique_ptr<ACryptoElement> asymmetric_cipher);
  bool IsAsymmetricCipherSet() const;
  ACryptoElement &GetAsymmetricCipher() const;
  const std::string &GetElementName() const override { return GetName(); };
  const std::string &GetElementTypeName() const override { return GetTypeName(); };
  static const uint16_t id = 2;
  static const std::string &GetName() {
    static std::string name = "asymmetric-cipher-scheme";
    return name;
  };
 private:
  std::unique_ptr<AAsymmetricCipher> asymmetric_cipher_;
};
}

#endif //HCL_SRC_SERVICES_CRYPTO_CIPHERS_ASYMMETRICCIPHERSCHEME_H_
