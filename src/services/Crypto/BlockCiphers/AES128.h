//
// Created by neodar on 06/04/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_BLOCKCIPHERS_AES128_H_
#define HCL_SRC_SERVICES_CRYPTO_BLOCKCIPHERS_AES128_H_

#include "../AutoRegisterer.h"
#include "ABlockCipher.h"
#include "Rijndael.h"

namespace HCL::Crypto {

class AES128 : public AutoRegisterer<ABlockCipher, AES128>, public Rijndael<16, 10> {
 public:
  AES128(const std::string &header, size_t &header_length) : Rijndael(header, header_length),
                                                             ABlockCipher(header, header_length) {
    is_registered_;
  };
  static const uint16_t Id = 1;
};
}

#endif //HCL_SRC_SERVICES_CRYPTO_BLOCKCIPHERS_AES128_H_
