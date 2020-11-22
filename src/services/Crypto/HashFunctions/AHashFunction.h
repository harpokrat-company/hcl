//
// Created by neodar on 06/04/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_HASHFUNCTIONS_AHASHFUNCTION_H_
#define HCL_SRC_SERVICES_CRYPTO_HASHFUNCTIONS_AHASHFUNCTION_H_

#include <string>
#include "../ACryptoElement.h"

namespace HCL::Crypto {

class AHashFunction : public ACryptoElement {
 public:
  ~AHashFunction() override = default;
  virtual std::string HashData(const std::string &data) = 0;
  [[nodiscard]] virtual size_t GetBlocSize() const = 0;
  virtual std::string GetHeader() = 0;
  [[nodiscard]] virtual uint8_t GetOutputSize() const = 0;
  static const std::string &GetName() {
    static std::string name = "hash-function";
    return name;
  };
};
}

#endif //HCL_SRC_SERVICES_CRYPTO_HASHFUNCTIONS_AHASHFUNCTION_H_
