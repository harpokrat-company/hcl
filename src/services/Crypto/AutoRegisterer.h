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
  virtual ~AutoRegisterer() = default;
  static std::unique_ptr<AbstractClass> InstantiateFromHeader(const std::string &header, size_t &header_length) {
    return std::make_unique<RegisteredClass>(header, header_length);
  }
  static std::unique_ptr<AbstractClass> Instantiate() {
    return std::make_unique<RegisteredClass>();
  }
  static uint16_t GetId() {
    return RegisteredClass::id;
  }
  static const std::string &GetRegisteredName() {
    return RegisteredClass::GetName();
  }
  static const std::string &GetTypeName() {
    return AbstractClass::GetName();
  }
  std::string GetIdBytes() {
    const char id[2] = {RegisteredClass::id >> 8, RegisteredClass::id & 0xFF};

    return std::string(id, 2);
  }
 protected:
  static const bool is_registered_;
};

template<typename AbstractClass, typename RegisteredClass>
const bool AutoRegisterer<AbstractClass, RegisteredClass>::is_registered_ =
    Factory<AbstractClass>::Register(RegisteredClass::id,
                                     &AutoRegisterer<AbstractClass, RegisteredClass>::InstantiateFromHeader,
                                     &AutoRegisterer<AbstractClass, RegisteredClass>::Instantiate,
                                     GetRegisteredName());
}

#endif //HCL_SRC_SERVICES_CRYPTO_CIPHERS_AUTOREGISTERER_H_
