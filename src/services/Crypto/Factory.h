//
// Created by neodar on 06/04/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_FACTORY_H_
#define HCL_SRC_SERVICES_CRYPTO_FACTORY_H_

#include <memory>
#include <map>
#include <iostream>
#include "Ciphers/ACipher.h"
#include "AFactory.h"
#include "SuperFactory.h"

namespace HCL::Crypto {

template<typename AbstractClass>
using HeaderInstantiator = std::unique_ptr<AbstractClass> (*)(const std::string &, size_t &);

template<typename AbstractClass>
using Instantiator = std::unique_ptr<AbstractClass> (*)();

template<typename AbstractClass>
class Factory : public AFactory {
 public:
  std::unique_ptr<AutoRegistrable> BuildFromHeader(const std::string &header, size_t &header_length) override;
  std::unique_ptr<AutoRegistrable> BuildFromId(uint16_t id) override;
  std::unique_ptr<AutoRegistrable> BuildFromName(const std::string &name) override;
  const std::string &GetFactoryType() override
  __attribute__((const));
  static bool Register(uint16_t identifier,
                       HeaderInstantiator<AbstractClass> header_instantiator,
                       Instantiator<AbstractClass> instantiator,
                       const std::string &name);
  static std::unique_ptr<AbstractClass> BuildTypedFromHeader(const std::string &header, size_t &header_length);
  static std::unique_ptr<AbstractClass> BuildTypedFromId(uint16_t id);
  static std::unique_ptr<AbstractClass> BuildTypedFromName(const std::string &name);
  static AFactory &GetInstance() {
    static Factory<AbstractClass> instance;
    return instance;
  }
  static const std::map<std::string, uint16_t> &GetClassesNames() {
    return GetRegisteredClassesNames();
  }
 private:
  static std::map<uint16_t, HeaderInstantiator<AbstractClass>> &GetRegisteredClassesHeaderConstructors() {
    static std::map<uint16_t, HeaderInstantiator<AbstractClass>> registered_classes_header_constructors = {};
    return registered_classes_header_constructors;
  }
  static std::map<uint16_t, Instantiator<AbstractClass>> &GetRegisteredClassesSimpleConstructors() {
    static std::map<uint16_t, Instantiator<AbstractClass>> registered_classes_simple_constructors = {};
    return registered_classes_simple_constructors;
  }
  static std::map<std::string, uint16_t> &GetRegisteredClassesNames() {
    static std::map<std::string, uint16_t> registered_classes_names = {};
    return registered_classes_names;
  }
  static const bool is_registered_;
};
// TODO Cleaner runtime errors

template<typename AbstractClass>
bool Factory<AbstractClass>::Register(uint16_t identifier,
                                      HeaderInstantiator<AbstractClass> header_instantiator,
                                      Instantiator<AbstractClass> instantiator,
                                      const std::string &name) {
  std::pair<typename std::map<uint16_t, HeaderInstantiator<AbstractClass>>::iterator, bool> registered_header_pair =
      GetRegisteredClassesHeaderConstructors().insert(std::make_pair(identifier, header_instantiator));
  std::pair<typename std::map<uint16_t, Instantiator<AbstractClass>>::iterator, bool> registered_pair =
      GetRegisteredClassesSimpleConstructors().insert(std::make_pair(identifier, instantiator));
  GetRegisteredClassesNames()[std::string(name)] = identifier;
  return registered_pair.second & registered_header_pair.second & is_registered_;
}

template<typename AbstractClass>
std::unique_ptr<AbstractClass> Factory<AbstractClass>::BuildTypedFromHeader(const std::string &header,
                                                                            size_t &header_length) {
  uint16_t id = 0;

  if (header.length() < header_length + 2) {
    throw std::runtime_error("Crypto object factory: Incorrect blob header: Too short");
  }
  id = uint16_t(((uint8_t) header[header_length]) << 8 | (uint8_t) header[header_length + 1]);
  typename std::map<uint16_t, HeaderInstantiator<AbstractClass>>::iterator registered_pair =
      GetRegisteredClassesHeaderConstructors().find(id);
  if (registered_pair == GetRegisteredClassesHeaderConstructors().end()) {
    throw std::runtime_error(
        "Crypto object factory: Unknown Id (HCL Library may not be up to date)");
  }
  header_length += 2;
  return std::move(registered_pair->second(header, header_length));
}

template<typename AbstractClass>
std::unique_ptr<AbstractClass> Factory<AbstractClass>::BuildTypedFromId(uint16_t id) {
  typename std::map<uint16_t, Instantiator<AbstractClass>>::iterator registered_pair =
      GetRegisteredClassesSimpleConstructors().find(id);
  if (registered_pair == GetRegisteredClassesSimpleConstructors().end()) {
    throw std::runtime_error(
        "Crypto object factory: Unknown Id (HCL Library may not be up to date)");
  }
  return std::move(registered_pair->second());
}

template<typename AbstractClass>
std::unique_ptr<AbstractClass> Factory<AbstractClass>::BuildTypedFromName(const std::string &name) {
  typename std::map<std::string, uint16_t>::iterator registered_pair = GetRegisteredClassesNames().find(name);
  if (registered_pair == GetRegisteredClassesNames().end()) {
    throw std::runtime_error(
        "Crypto object factory: Unknown Name (HCL Library may not be up to date)");
  }
  return std::move(BuildTypedFromId(registered_pair->second));
}

template<typename AbstractClass>
std::unique_ptr<AutoRegistrable> Factory<AbstractClass>::BuildFromHeader(const std::string &header,
                                                                         size_t &header_length) {
  return std::move(Factory<AbstractClass>::BuildTypedFromHeader(header, header_length));
}

template<typename AbstractClass>
std::unique_ptr<AutoRegistrable> Factory<AbstractClass>::BuildFromId(uint16_t id) {
  return std::move(Factory<AbstractClass>::BuildTypedFromId(id));
}

template<typename AbstractClass>
std::unique_ptr<AutoRegistrable> Factory<AbstractClass>::BuildFromName(const std::string &name) {
  return std::move(Factory<AbstractClass>::BuildTypedFromName(name));
}

template<typename AbstractClass>
const std::string &Factory<AbstractClass>::GetFactoryType() {
  return AbstractClass::GetName();
}

template<typename AbstractClass>
const bool Factory<AbstractClass>::is_registered_ = SuperFactory::Register(AbstractClass::GetName(), GetInstance);
}

#endif //HCL_SRC_SERVICES_CRYPTO_FACTORY_H_
