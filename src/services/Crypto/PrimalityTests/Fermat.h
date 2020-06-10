//
// Created by antoine on 10/06/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_PRIMALITYTESTS_FERMAT_H_
#define HCL_SRC_SERVICES_CRYPTO_PRIMALITYTESTS_FERMAT_H_

#include "../AutoRegisterer.h"
#include "APrimalityTest.h"

namespace HCL::Crypto {

class Fermat : public AutoRegisterer<APrimalityTest, Fermat> {
 public:
  Fermat();
  Fermat(const std::string &header, size_t &header_length);
  //As there is no required dependencies, override with errors
  const std::vector<std::string> &GetDependenciesTypes() override {
	static const std::vector<std::string> dependencies({});
	return dependencies;
  }
  void SetDependency(std::unique_ptr<ACryptoElement> dependency, size_t index) override {
	throw std::runtime_error(GetDependencyIndexError("set"));
  }
  bool IsDependencySet(size_t index) override {
	throw std::runtime_error(GetDependencyIndexError("check"));
  }
  ACryptoElement &GetDependency(size_t index) override {
	throw std::runtime_error(GetDependencyIndexError("get"));
  }
  //
  bool IsPrime(size_t number) override;
  //
  std::string GetHeader() override;
  const std::string &GetElementName() const override { return GetName(); };
  const std::string &GetElementTypeName() const override { return GetTypeName(); };
  static const uint16_t id = 1;
  static const std::string &GetName() {
	static std::string name = "fermat";
	return name;
  };
 private:
};

}
#endif //HCL_SRC_SERVICES_CRYPTO_PRIMALITYTESTS_FERMAT_H_
