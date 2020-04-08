//
// Created by neodar on 08/04/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_ACRYPTOELEMENT_H_
#define HCL_SRC_SERVICES_CRYPTO_ACRYPTOELEMENT_H_

#include <vector>
#include <string>
#include <map>
#include <memory>

namespace HCL::Crypto {

class ACryptoElement {
 public:
  // TODO Clean runtime errors
  virtual const std::vector<std::string> &GetRequiredDependencies() = 0;
  virtual void SetDependency(std::unique_ptr<ACryptoElement> dependency, size_t index) = 0;
  // TODO ? virtual const std::string &GetDependency(size_t index) = 0;
  virtual const std::string &GetElementName() = 0;
  virtual const std::string &GetElementTypeName() = 0;
  template <typename DerivedClass>
  static std::unique_ptr<DerivedClass> UniqueTo(std::unique_ptr<ACryptoElement> auto_registrable) {
    return std::unique_ptr<DerivedClass>(dynamic_cast<DerivedClass *>(auto_registrable.release()));
  }
};
}

#endif //HCL_SRC_SERVICES_CRYPTO_ACRYPTOELEMENT_H_
