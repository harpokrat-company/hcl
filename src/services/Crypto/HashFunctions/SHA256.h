//
// Created by neodar on 07/04/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_HASHFUNCTIONS_SHA256_H_
#define HCL_SRC_SERVICES_CRYPTO_HASHFUNCTIONS_SHA256_H_

#include "../AutoRegisterer.h"
#include "AHashFunction.h"

namespace HCL::Crypto {

#define RIGHT_SHIFT(x, n)   ((x) >> (n))
#define RIGHT_ROTATE(x, n)  (((x) >> (n)) | ((x) << ((sizeof(x) << 3) - (n))))
#define CH(x)               (((x)[4] & (x)[5]) ^ ((~((x)[4])) & (x)[6]))
#define MAJ(x)              (((x)[0] & (x)[1]) ^ ((x)[0] & (x)[2]) ^ ((x)[1] & (x)[2]))
#define SHA256_s0(x)        (RIGHT_ROTATE(x,  7) ^ RIGHT_ROTATE(x, 18) ^ RIGHT_SHIFT(x,  3))
#define SHA256_s1(x)        (RIGHT_ROTATE(x, 17) ^ RIGHT_ROTATE(x, 19) ^ RIGHT_SHIFT(x, 10))
#define SHA256_S0(x)        (RIGHT_ROTATE(x,  2) ^ RIGHT_ROTATE(x, 13) ^ RIGHT_ROTATE(x, 22))
#define SHA256_S1(x)        (RIGHT_ROTATE(x,  6) ^ RIGHT_ROTATE(x, 11) ^ RIGHT_ROTATE(x, 25))

class SHA256 : public AutoRegisterer<AHashFunction, SHA256> {
  // TODO Make changes for re-use in different SHA2
 public:
  SHA256(const std::string &header, size_t &header_length) {
    is_registered_;
  };
  const std::vector<std::string> &GetRequiredDependencies() override {
    static const std::vector<std::string> dependencies({});
    return dependencies;
  }
  void SetDependency(std::unique_ptr<AutoRegistrable> dependency, size_t index) override {
      throw std::runtime_error("SHA256 error: Cannot set dependency: Incorrect dependency index");
  }
  virtual std::string HashData(const std::string &data);
  virtual size_t GetBlocSize() __attribute__((const));
  std::string GetHeader() override;
  static const uint16_t id = 1;
  static const std::string &GetName() {
    static std::string name = "sha256";
    return name;
  };
 private:
  std::string PadData(const std::string &data);
  static const uint32_t round_constants_[64];
};

}

#endif //HCL_SRC_SERVICES_CRYPTO_HASHFUNCTIONS_SHA256_H_
