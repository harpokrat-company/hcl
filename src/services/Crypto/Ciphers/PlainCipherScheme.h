//
// Created by neodar on 06/04/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_CIPHERS_PLAINCIPHERSCHEME_H_
#define HCL_SRC_SERVICES_CRYPTO_CIPHERS_PLAINCIPHERSCHEME_H_

#include <stdexcept>
#include "ACipher.h"
#include "../AutoRegisterer.h"

namespace HCL::Crypto {

class PlainCipherScheme : public AutoRegisterer<ACipher, PlainCipherScheme> {
 public:
  PlainCipherScheme() = default;
  PlainCipherScheme(const std::string &header, size_t &header_length);
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
  std::string Encrypt(const ICipherEncryptionKey *key, const std::string &content) override;
  std::string Decrypt(const ICipherDecryptionKey *key, const std::string &content) override;
  std::string GetHeader() override;
  const std::string &GetElementName() const override { return GetName(); };
  const std::string &GetElementTypeName() const override { return GetTypeName(); };
  static const uint16_t id = 3;
  static const std::string &GetName() {
    static std::string name = "plain-cipher-scheme";
    return name;
  };
};
}

#endif //HCL_SRC_SERVICES_CRYPTO_CIPHERS_PLAINCIPHERSCHEME_H_
