//
// Created by neodar on 06/04/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_BLOCKCIPHERS_AES256_H_
#define HCL_SRC_SERVICES_CRYPTO_BLOCKCIPHERS_AES256_H_

#include "../AutoRegisterer.h"
#include "ABlockCipher.h"
#include "Rijndael.h"

namespace HCL::Crypto {

class AES256 : public AutoRegisterer<ABlockCipher, AES256>, public Rijndael<32, 14> {
 public:
  AES256() : Rijndael() {};
  static const uint16_t Id = 3;
};
}

#endif //HCL_SRC_SERVICES_CRYPTO_BLOCKCIPHERS_AES256_H_
