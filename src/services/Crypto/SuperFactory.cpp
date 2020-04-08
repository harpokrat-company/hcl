//
// Created by neodar on 06/04/2020.
//

#include <iostream>
#include "SuperFactory.h"

bool HCL::Crypto::SuperFactory::Register(const std::string &type,
                                         HCL::Crypto::FactoryInstanceGetter factory_instance_getter) {
  std::pair<typename std::map<std::string, FactoryInstanceGetter >::iterator, bool> registered_pair =
      GetRegisteredFactories().insert(std::make_pair(type, factory_instance_getter));
  GetRegisteredFactoriesTypes().push_back(type);
  return registered_pair.second;
}

HCL::Crypto::AFactory &HCL::Crypto::SuperFactory::GetFactoryOfType(const std::string &type) {
  auto registered_pair = GetRegisteredFactories().find(type);
  if (registered_pair == GetRegisteredFactories().end()) {
    throw std::runtime_error(
        std::string("Super Factory: Cannot get factory instance: Unregistered factory type \"") + type + "\"");
  }
  return registered_pair->second();
}
