//
// Created by neodar on 06/04/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_KEYSTRETCHING_AKEYSTRETCHING_H_
#define HCL_SRC_SERVICES_CRYPTO_KEYSTRETCHING_AKEYSTRETCHING_H_

#include <string>

namespace HCL::Crypto {

class AKeyStretching {
 public:
  virtual std::string StretchKey(const std::string &key, size_t derived_key_length) = 0;
};
}

#endif //HCL_SRC_SERVICES_CRYPTO_KEYSTRETCHING_AKEYSTRETCHING_H_
