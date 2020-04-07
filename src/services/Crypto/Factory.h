//
// Created by neodar on 06/04/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_FACTORY_H_
#define HCL_SRC_SERVICES_CRYPTO_FACTORY_H_

#include <memory>
#include <map>
#include <iostream>
#include "Ciphers/ACipher.h"

namespace HCL::Crypto {

template<typename AbstractClass>
using Instantiator = std::unique_ptr<AbstractClass> (*)(const std::string &, size_t &);

template<typename AbstractClass>
class Factory {
 public:
  static bool Register(uint16_t identifier, Instantiator<AbstractClass> instantiator, const std::string &name);
  static std::unique_ptr<AbstractClass> GetInstanceFromHeader(const std::string &, size_t &);
  static const std::string &GetFactoryAbstractType() __attribute__((const));
  static const std::map<std::string, uint16_t> &GetClassesNames() {
    return GetRegisteredClassesNames();
  }
  // TODO Add getInstanceFromId without header ?
 private:
  static std::map<uint16_t, Instantiator<AbstractClass>> &GetRegisteredClasses() {
    static std::map<uint16_t, Instantiator<AbstractClass>> registered_classes = {};
    return registered_classes;
  };
  static std::map<std::string, uint16_t> &GetRegisteredClassesNames() {
    static std::map<std::string, uint16_t> registered_classes_names = {};
    return registered_classes_names;
  };
};

template<typename AbstractClass>
bool Factory<AbstractClass>::Register(uint16_t identifier,
                                      Instantiator<AbstractClass> instantiator,
                                      const std::string &name) {
  std::pair<typename std::map<uint16_t, Instantiator<AbstractClass>>::iterator, bool> registered_pair =
      Factory<AbstractClass>::GetRegisteredClasses().insert(std::make_pair(identifier, instantiator));
  Factory<AbstractClass>::GetRegisteredClassesNames()[std::string(name)] = identifier;
  return registered_pair.second;
}

template<typename AbstractClass>
std::unique_ptr<AbstractClass> Factory<AbstractClass>::GetInstanceFromHeader(const std::string &header,
                                                                             size_t &header_length) {
  uint16_t id = 0;

  if (header.length() < header_length + 2) {
    throw std::runtime_error("Crypto object factory: Incorrect blob header: Too short");
  }
  id = uint16_t(((uint8_t) header[header_length]) << 8 | (uint8_t) header[header_length + 1]);
  typename std::map<uint16_t, Instantiator<AbstractClass>>::iterator registered_pair = GetRegisteredClasses().find(id);
  if (registered_pair == GetRegisteredClasses().end()) {
    throw std::runtime_error(
        "Crypto object factory: Incorrect blob header: Unknown Id (HCL Library may not be up to date)");
  }
  header_length += 2;
  return registered_pair->second(header, header_length);
}

template<typename AbstractClass>
const std::string &Factory<AbstractClass>::GetFactoryAbstractType() {
  return AbstractClass::GetName();
}
}

#endif //HCL_SRC_SERVICES_CRYPTO_FACTORY_H_
