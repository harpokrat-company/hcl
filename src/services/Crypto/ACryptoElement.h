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
  virtual ~ACryptoElement() = default;
  // TODO Clean runtime errors
  virtual const std::vector<std::string> &GetDependenciesTypes() = 0;
  // TODO SetDependency via name of element (& call to factory)
  // TODO SetParameter system with different possible types of variable and boundaries for numbers
  virtual void SetDependency(std::unique_ptr<ACryptoElement> dependency, size_t index) = 0;
  virtual bool IsDependencySet(size_t index) = 0;
  virtual const ACryptoElement &GetDependency(size_t index) = 0;
  virtual const std::string &GetElementName() = 0;
  virtual const std::string &GetElementTypeName() = 0;
  template <typename DerivedClass>
  static std::unique_ptr<DerivedClass> UniqueTo(std::unique_ptr<ACryptoElement> auto_registrable) {
    return std::unique_ptr<DerivedClass>(dynamic_cast<DerivedClass *>(auto_registrable.release()));
  }
};
}

#endif //HCL_SRC_SERVICES_CRYPTO_ACRYPTOELEMENT_H_
