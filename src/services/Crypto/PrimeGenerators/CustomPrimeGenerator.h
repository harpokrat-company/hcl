//
// Created by antoine on 27/06/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_PRIMEGENERATORS_CUSTOMPRIMEGENERATOR_H_
#define HCL_SRC_SERVICES_CRYPTO_PRIMEGENERATORS_CUSTOMPRIMEGENERATOR_H_

#include <stdexcept>
#include "../AutoRegisterer.h"
#include "APrimeGenerator.h"

namespace HCL::Crypto {

class CustomPrimeGenerator : public AutoRegisterer<APrimeGenerator, CustomPrimeGenerator> {
 public:
  CustomPrimeGenerator();
  CustomPrimeGenerator(const std::string &header, size_t &header_length);
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
  __mpz_struct GenerateRandomPrime(size_t bits) override;
  std::string GetHeader() override;
  const std::string &GetElementName() const override { return GetName(); };
  const std::string &GetElementTypeName() const override { return GetTypeName(); };
  static const uint16_t id = 1;
  static const std::string &GetName() {
	static std::string name = "custom-prime-generator";
	return name;
  };
 private:
  gmp_randstate_t r1;
};
}
#endif //HCL_SRC_SERVICES_CRYPTO_PRIMEGENERATORS_CUSTOMPRIMEGENERATOR_H_
