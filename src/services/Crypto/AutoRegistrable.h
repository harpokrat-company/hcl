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
  virtual const std::vector<std::string> &GetDependencies() = 0;
  void SetDependency(std::unique_ptr<AutoRegistrable> dependency, size_t index) {
    auto registered_pair = GetDependencySetters().find(index);
    if (registered_pair == GetDependencySetters().end()) {
      throw std::runtime_error("AutoRegistrable error: Cannot set dependency: Incorrect dependency index");
    }
    GetDependencySetters().at(index)(std::move(dependency));
  }
  template <typename DerivedClass>
  static std::unique_ptr<DerivedClass> UniqueTo(std::unique_ptr<AutoRegistrable> auto_registrable) {
    return std::unique_ptr<DerivedClass>(dynamic_cast<DerivedClass *>(auto_registrable.release()));
  }
 protected:
  virtual const std::map<size_t, void (*)(std::unique_ptr<AutoRegistrable>)> &GetDependencySetters() = 0;
};
}

#endif //HCL_SRC_SERVICES_CRYPTO_AUTOREGISTRABLE_H_
