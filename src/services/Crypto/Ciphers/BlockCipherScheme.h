//
// Created by neodar on 06/04/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_CIPHERS_BLOCKCIPHERSCHEME_H_
#define HCL_SRC_SERVICES_CRYPTO_CIPHERS_BLOCKCIPHERSCHEME_H_

#include "ACipher.h"
#include "../AutoRegisterer.h"
#include "../BlockCipherModes/ABlockCipherMode.h"

namespace HCL::Crypto {

class BlockCipherScheme : public AutoRegisterer<ACipher, BlockCipherScheme> {
 public:
  BlockCipherScheme() = default;
  BlockCipherScheme(const std::string &header, size_t &header_length);
  const std::vector<std::string> &GetDependenciesTypes() override {
    static const std::vector<std::string> dependencies(
        {
            ABlockCipherMode::GetName(),
        });
    return dependencies;
  }
  void SetDependency(std::unique_ptr<ACryptoElement> dependency, size_t index) override {
    if (index >= 1) {
      throw std::runtime_error("BlockCipherScheme error: Cannot set dependency: Incorrect dependency index");
    }
    switch (index) {
      case 0:
      default:SetBlockCipherMode(std::move(dependency));
    }
  }
  bool IsDependencySet(size_t index) override {
    if (index >= 1) {
      throw std::runtime_error("BlockCipherScheme error: Cannot check dependency: Incorrect dependency index");
    }
    switch (index) {
      case 0:
      default:return IsBlockCipherModeSet();
    }
  }
  ACryptoElement &GetDependency(size_t index) override {
    if (index >= 1) {
      throw std::runtime_error("BlockCipherScheme error: Cannot get dependency: Incorrect dependency index");
    }
    switch (index) {
      case 0:
      default:return GetBlockCipherMode();
    }
  }
  std::string Encrypt(const std::string &key, const std::string &content) override;
  std::string Decrypt(const std::string &key, const std::string &content) override;
  std::string GetHeader() override;
  void SetBlockCipherMode(std::unique_ptr<ACryptoElement> block_cipher_mode);
  bool IsBlockCipherModeSet() const;
  ACryptoElement &GetBlockCipherMode() const;
  const std::string &GetElementName() override { return GetName(); };
  const std::string &GetElementTypeName() override { return GetTypeName(); };
  static const uint16_t id = 1;
  static const std::string &GetName() {
    static std::string name = "block-cipher-scheme";
    return name;
  };
 private:
  std::unique_ptr<ABlockCipherMode> block_cipher_mode_;
};
}

#endif //HCL_SRC_SERVICES_CRYPTO_CIPHERS_BLOCKCIPHERSCHEME_H_
