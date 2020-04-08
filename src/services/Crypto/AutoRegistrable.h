//
// Created by neodar on 08/04/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_AUTOREGISTRABLE_H_
#define HCL_SRC_SERVICES_CRYPTO_AUTOREGISTRABLE_H_

#include <vector>
#include <string>
#include <map>
#include <memory>

namespace HCL::Crypto {

class AutoRegistrable {
 public:
  // TODO virtual get Name / Type name ?
  // TODO Clean runtime errors
  virtual const std::vector<std::string> &GetRequiredDependencies() = 0;
  virtual void SetDependency(std::unique_ptr<AutoRegistrable> dependency, size_t index) = 0;
  template <typename DerivedClass>
  static std::unique_ptr<DerivedClass> UniqueTo(std::unique_ptr<AutoRegistrable> auto_registrable) {
    return std::unique_ptr<DerivedClass>(dynamic_cast<DerivedClass *>(auto_registrable.release()));
  }
};
}

#endif //HCL_SRC_SERVICES_CRYPTO_AUTOREGISTRABLE_H_
