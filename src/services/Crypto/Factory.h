//
// Created by neodar on 06/04/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_FACTORY_H_
#define HCL_SRC_SERVICES_CRYPTO_FACTORY_H_

#include <memory>
#include <map>
#include "Ciphers/ACipher.h"

namespace HCL::Crypto {

template<typename AbstractClass>
using Instantiator = std::unique_ptr<AbstractClass> (*)(const std::string &, size_t &);

template<typename AbstractClass>
class Factory {
 public:
  static bool Register(uint16_t identifier, Instantiator<AbstractClass>);
  static std::unique_ptr<AbstractClass> GetInstanceFromHeader(const std::string &, size_t &);
  // TODO Add getInstanceFromId without header ? Maybe via second factory ?
 private:
  static std::map<uint16_t, Instantiator<AbstractClass>> registered_classes_;
};

template<typename AbstractClass>
bool Factory<AbstractClass>::Register(uint16_t identifier, Instantiator<AbstractClass> instantiator) {
  std::pair<typename std::map<uint16_t, Instantiator<AbstractClass>>::iterator, bool> registered_pair =
      Factory<AbstractClass>::registered_classes_.insert(std::make_pair(identifier, instantiator));
  return registered_pair.second;
}

template<typename AbstractClass>
std::unique_ptr<AbstractClass> Factory<AbstractClass>::GetInstanceFromHeader(const std::string &header,
                                                                             size_t &header_length) {
  uint16_t id = 0;

  if (header.length() < 2) {
    return std::unique_ptr<AbstractClass>{};
  }
  id = uint16_t(((uint8_t) header[0]) << 8 | (uint8_t) header[1]);
  typename std::map<uint16_t, Instantiator<AbstractClass>>::iterator registered_pair = registered_classes_.find(id);
  if (registered_pair == registered_classes_.end()) {
    return std::unique_ptr<AbstractClass>{};
  }
  header_length += 2;
  return registered_pair->second(header.substr(2), header_length);
}

template<typename AbstractClass>
std::map<uint16_t, Instantiator<AbstractClass>> Factory<AbstractClass>::registered_classes_ = {};
}

#endif //HCL_SRC_SERVICES_CRYPTO_FACTORY_H_
