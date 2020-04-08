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
  BlockCipherScheme(const std::string &header, size_t &header_length);
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
  std::string Encrypt(const std::string &key, const std::string &content) override;
  std::string Decrypt(const std::string &key, const std::string &content) override;
  std::string GetHeader() override;
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
