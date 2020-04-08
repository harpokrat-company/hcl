//
// Created by neodar on 06/04/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_KEYSTRETCHINGFUNCTIONS_AKEYSTRETCHINGFUNCTION_H_
#define HCL_SRC_SERVICES_CRYPTO_KEYSTRETCHINGFUNCTIONS_AKEYSTRETCHINGFUNCTION_H_

#include <string>
#include "../AutoRegistrable.h"

namespace HCL::Crypto {

class AKeyStretchingFunction : public AutoRegistrable {
 public:
  virtual std::string StretchKey(const std::string &key, size_t derived_key_length) = 0;
  virtual std::string GetHeader() = 0;
  static const std::string &GetName() {
    static std::string name = "key-stretching-function";
    return name;
  };
};
}

#endif //HCL_SRC_SERVICES_CRYPTO_KEYSTRETCHINGFUNCTIONS_AKEYSTRETCHINGFUNCTION_H_
