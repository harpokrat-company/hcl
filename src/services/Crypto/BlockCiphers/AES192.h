//
// Created by neodar on 06/04/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_BLOCKCIPHERS_AES192_H_
#define HCL_SRC_SERVICES_CRYPTO_BLOCKCIPHERS_AES192_H_

#include "../AutoRegisterer.h"
#include "ABlockCipher.h"
#include "Rijndael.h"

namespace HCL::Crypto {

class AES192 : public AutoRegisterer<ABlockCipher, AES192>, public Rijndael<24, 12> {
 public:
  AES192() : Rijndael() {};
  static const uint16_t Id = 2;
};
}

#endif //HCL_SRC_SERVICES_CRYPTO_BLOCKCIPHERS_AES192_H_
