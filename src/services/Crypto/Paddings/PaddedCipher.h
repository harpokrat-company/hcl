//
// Created by neodar on 06/04/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_PADDINGS_PADDEDCIPHER_H_
#define HCL_SRC_SERVICES_CRYPTO_PADDINGS_PADDEDCIPHER_H_

#include <string>
#include <memory>
#include "APadding.h"

namespace HCL::Crypto {

class PaddedCipher {
 public:
  PaddedCipher(const std::string &header, size_t &header_length);
 protected:
  std::unique_ptr<APadding> padding_;
};
}

#endif //HCL_SRC_SERVICES_CRYPTO_PADDINGS_PADDEDCIPHER_H_
