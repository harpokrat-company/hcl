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

#define CRYPTO_ELEMENT_ERROR_ACTION_SET_DEPENDENCY

class ACryptoElement {
 public:
  virtual ~ACryptoElement() = default;
  // TODO SetParameter system with different possible types of variable and boundaries for numbers
  virtual const std::vector<std::string> &GetDependenciesTypes() = 0;
  virtual void SetDependency(std::unique_ptr<ACryptoElement> dependency, size_t index) = 0;
  void InstantiateDependency(const std::string &name, size_t index);
  virtual bool IsDependencySet(size_t index) = 0;
  virtual ACryptoElement &GetDependency(size_t index) = 0;
  virtual const std::string &GetElementName() const = 0;
  virtual const std::string &GetElementTypeName() const = 0;
  std::string GetError(const std::string &action, const std::string &details) const;
  std::string GetDependencyIndexError(const std::string &action) const;
  std::string GetDependencyUnsetError(const std::string &action, const std::string &dependency) const;
  template <typename DerivedClass>
  static std::unique_ptr<DerivedClass> UniqueTo(std::unique_ptr<ACryptoElement> auto_registrable) {
    return std::unique_ptr<DerivedClass>(dynamic_cast<DerivedClass *>(auto_registrable.release()));
  }
};
}

#endif //HCL_SRC_SERVICES_CRYPTO_ACRYPTOELEMENT_H_
