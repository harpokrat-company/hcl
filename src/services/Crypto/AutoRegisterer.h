//
// Created by neodar on 06/04/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_CIPHERS_AUTOREGISTERER_H_
#define HCL_SRC_SERVICES_CRYPTO_CIPHERS_AUTOREGISTERER_H_

#include "Factory.h"

namespace HCL::Crypto {

template<typename AbstractClass, typename RegisteredClass>
class AutoRegisterer : virtual public AbstractClass {
 public:
  static std::unique_ptr<AbstractClass> InstantiateFromHeader(const std::string &header, size_t &header_length) {
    return std::make_unique<RegisteredClass>(header, header_length);
  }
  uint16_t GetId() {
    return RegisteredClass::Id;
  }
  std::string GetIdBytes() {
    const char id[2] = {RegisteredClass::Id & 0xFF, RegisteredClass::Id >> 8};

    return std::string(id, 2);
  }
 protected:
  static const bool is_registered_;
};

template<typename AbstractClass, typename RegisteredClass>
const bool HCL::Crypto::AutoRegisterer<AbstractClass, RegisteredClass>::is_registered_ =
    Factory<AbstractClass>::Register(RegisteredClass::Id,
                                     &AutoRegisterer<AbstractClass, RegisteredClass>::InstantiateFromHeader);
}

#endif //HCL_SRC_SERVICES_CRYPTO_CIPHERS_AUTOREGISTERER_H_
