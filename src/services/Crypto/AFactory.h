//
// Created by neodar on 08/04/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_AFACTORY_H_
#define HCL_SRC_SERVICES_CRYPTO_AFACTORY_H_

#include <memory>
#include <string>
#include "ACryptoElement.h"

namespace HCL::Crypto {

class AFactory {
 public:
  virtual std::unique_ptr<ACryptoElement> BuildFromHeader(const std::string &header, size_t &header_length) = 0;
  virtual std::unique_ptr<ACryptoElement> BuildFromId(uint16_t id) = 0;
  virtual std::unique_ptr<ACryptoElement> BuildFromName(const std::string &name) = 0;
  virtual const std::string &GetFactoryType() __attribute__((const)) = 0;
};

using FactoryInstanceGetter = AFactory &(*)();
}

#endif //HCL_SRC_SERVICES_CRYPTO_AFACTORY_H_
