//
// Created by neodar on 06/04/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_BLOCKCIPHERS_AES256_H_
#define HCL_SRC_SERVICES_CRYPTO_BLOCKCIPHERS_AES256_H_

#include "../AutoRegisterer.h"
#include "ABlockCipher.h"
#include "Rijndael.h"

namespace HCL::Crypto {

class AES256 : public AutoRegisterer<ABlockCipher, AES256>, public Rijndael<32, 14> {
 public:
  AES256(const std::string &header, size_t &header_length) : Rijndael<32, 14>(header, header_length) {
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
  std::string GetHeader() override;
  static const uint16_t id = 3;
  static const std::string &GetName() {
    static std::string name = "aes256";
    return name;
  };
};
}

#endif //HCL_SRC_SERVICES_CRYPTO_BLOCKCIPHERS_AES256_H_
