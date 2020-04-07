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
    return RegisteredClass::id;
  }
  std::string GetName() {
    return RegisteredClass::name;
  }
  std::string GetTypeName() {
    return AbstractClass::type_name;
  }
  std::string GetIdBytes() {
    const char id[2] = {RegisteredClass::id & 0xFF, RegisteredClass::id >> 8};

    return std::string(id, 2);
  }
 protected:
  static const bool is_registered_;
};

template<typename AbstractClass, typename RegisteredClass>
const bool HCL::Crypto::AutoRegisterer<AbstractClass, RegisteredClass>::is_registered_ =
    Factory<AbstractClass>::Register(RegisteredClass::id,
                                     &AutoRegisterer<AbstractClass, RegisteredClass>::InstantiateFromHeader);
}

#endif //HCL_SRC_SERVICES_CRYPTO_CIPHERS_AUTOREGISTERER_H_
