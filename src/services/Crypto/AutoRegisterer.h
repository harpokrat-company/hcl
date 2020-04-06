//
// Created by neodar on 06/04/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_CIPHERS_AUTOREGISTERER_H_
#define HCL_SRC_SERVICES_CRYPTO_CIPHERS_AUTOREGISTERER_H_

#include "Ciphers/ACipher.h"
#include "Factory.h"

namespace HCL::Crypto {

template<typename AbstractClass, typename RegisteredClass>
class AutoRegisterer : public AbstractClass {
 public:
  static std::unique_ptr<ACipher> InstantiateFromHeader(const std::string &header, size_t &header_length) {
    return std::make_unique<RegisteredClass>(header, header_length);
  }
  uint16_t GetId() {
    return RegisteredClass::Id;
  }
 protected:
  static const bool is_registered_;
};

template<typename AbstractClass, typename RegisteredClass>
const bool HCL::Crypto::AutoRegisterer<AbstractClass, RegisteredClass>::is_registered_ =
    Factory<AbstractClass>::RegisterCipher(RegisteredClass::Id,
                                           &AutoRegisterer<AbstractClass, RegisteredClass>::InstantiateFromHeader);
}

#endif //HCL_SRC_SERVICES_CRYPTO_CIPHERS_AUTOREGISTERER_H_
