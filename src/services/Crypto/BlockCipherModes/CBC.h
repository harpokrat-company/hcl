//
// Created by neodar on 06/04/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_BLOCKCIPHERMODES_CBC_H_
#define HCL_SRC_SERVICES_CRYPTO_BLOCKCIPHERMODES_CBC_H_

#include "ABlockCipherMode.h"
#include "../AutoRegisterer.h"
#include "../Paddings/PaddedCipher.h"

namespace HCL::Crypto {

class CBC : public AutoRegisterer<ABlockCipherMode, CBC>, public PaddedCipher {
 public:
  CBC(const std::string &header, size_t &header_length);
  static const uint16_t Id = 1;
};
}

#endif //HCL_SRC_SERVICES_CRYPTO_BLOCKCIPHERMODES_CBC_H_
