//
// Created by neodar on 07/04/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_HASHFUNCTIONS_SHA384_H_
#define HCL_SRC_SERVICES_CRYPTO_HASHFUNCTIONS_SHA384_H_

#include "../AutoRegisterer.h"
#include "AHashFunction.h"
#include "SHA2.h"
#include "SHA512.h"

namespace HCL::Crypto {

class SHA384 : public AutoRegisterer<AHashFunction, SHA384>, public SHA512 {
 public:
  SHA384() = default;
  SHA384(const std::string &header, size_t &header_length) {};
  ~SHA384() override = default;
  void SetDependency(std::unique_ptr<ACryptoElement> dependency, size_t index) override {
    throw std::runtime_error("SHA384 error: Cannot set dependency: Incorrect dependency index");
  }
  static const uint16_t id = 4;
  static const std::string &GetName() {
    static std::string name = "sha384";
    return name;
  };
 protected:
  uint64_t GetHashValue(size_t index) const override {
    static const uint64_t hash_values[8] = {
        0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939,
        0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4
    };
    return hash_values[index];
  }
  uint8_t GetMaxOutputHash() const override {
    return 6;
  };
};
}

#endif //HCL_SRC_SERVICES_CRYPTO_HASHFUNCTIONS_SHA384_H_
