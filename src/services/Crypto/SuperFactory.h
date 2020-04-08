//
// Created by neodar on 06/04/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_SUPERFACTORY_H_
#define HCL_SRC_SERVICES_CRYPTO_SUPERFACTORY_H_

#include <vector>
#include <map>
#include "AFactory.h"

namespace HCL::Crypto {

class SuperFactory {
 public:
  static bool Register(const std::string &, FactoryInstanceGetter);
  static AFactory &GetFactoryOfType(const std::string &);
  static const std::vector<std::string> &GetFactoryTypes() {
    return GetRegisteredFactoriesTypes();
  }
 private:
  static std::map<std::string, FactoryInstanceGetter> &GetRegisteredFactories() {
    static std::map<std::string, FactoryInstanceGetter> registered_factories = {};
    return registered_factories;
  }
  static std::vector<std::string> &GetRegisteredFactoriesTypes() {
    static std::vector<std::string> registered_factories_types = {};
    return registered_factories_types;
  }
};
}

#endif //HCL_SRC_SERVICES_CRYPTO_SUPERFACTORY_H_
