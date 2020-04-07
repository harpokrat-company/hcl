//
// Created by neodar on 06/04/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_HASHFUNCTIONS_AHASHFUNCTION_H_
#define HCL_SRC_SERVICES_CRYPTO_HASHFUNCTIONS_AHASHFUNCTION_H_

#include <string>

namespace HCL::Crypto {

class AHashFunction {
 public:
  virtual std::string HashData(const std::string &data) = 0;
  virtual size_t GetBlocSize() __attribute__((const)) = 0;
  virtual std::string GetHeader() = 0;
};
}

#endif //HCL_SRC_SERVICES_CRYPTO_HASHFUNCTIONS_AHASHFUNCTION_H_
