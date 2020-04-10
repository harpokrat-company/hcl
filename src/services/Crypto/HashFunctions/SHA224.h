//
// Created by neodar on 07/04/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_HASHFUNCTIONS_SHA224_H_
#define HCL_SRC_SERVICES_CRYPTO_HASHFUNCTIONS_SHA224_H_

#include "../AutoRegisterer.h"
#include "AHashFunction.h"
#include "SHA2.h"
#include "SHA256.h"

namespace HCL::Crypto {

class SHA224 : public AutoRegisterer<AHashFunction, SHA224>, public SHA256 {
 public:
  SHA224() = default;
  SHA224(const std::string &header, size_t &header_length) {};
  ~SHA224() override = default;
  void SetDependency(std::unique_ptr<ACryptoElement> dependency, size_t index) override {
    throw std::runtime_error("SHA224 error: Cannot set dependency: Incorrect dependency index");
  }
  static const uint16_t id = 3;
  static const std::string &GetName() {
    static std::string name = "sha224";
    return name;
  };
 protected:
  uint32_t GetHashValue(size_t index) const override {
    static const uint32_t hash_values[8] = {
        0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
    };
    return hash_values[index];
  }
  uint8_t GetOutputSize() const override {
    return 28;
  };
};
}

#endif //HCL_SRC_SERVICES_CRYPTO_HASHFUNCTIONS_SHA224_H_
