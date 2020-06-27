//
// Created by antoine on 27/06/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_PRIMEGENERATORS_CUSTOMPRIMEGENERATOR_H_
#define HCL_SRC_SERVICES_CRYPTO_PRIMEGENERATORS_CUSTOMPRIMEGENERATOR_H_

#include "../AutoRegisterer.h"
#include "APrimeGenerator.h"
#include "../PrimalityTests/APrimalityTest.h"
#include "../RandomGenerators/ARandomGenerator.h"

namespace HCL::Crypto {

class CustomPrimeGenerator : public AutoRegisterer<APrimeGenerator, CustomPrimeGenerator> {
 public:
  CustomPrimeGenerator();
  CustomPrimeGenerator(const std::string &header, size_t &header_length);
  const std::vector<std::string> &GetDependenciesTypes() override {
	static const std::vector<std::string> dependencies(
		{
			ARandomGenerator::GetName(),
			APrimalityTest::GetName(),
		});
	return dependencies;
  }
  void SetDependency(std::unique_ptr<ACryptoElement> dependency, size_t index) override {
	if (index >= 2) {
	  throw std::runtime_error(GetDependencyIndexError("set"));
	}
	switch (index) {
	  case 0:SetRandomGenerator(std::move(dependency));
	  case 1:
	  default:SetPrimalityTest(std::move(dependency));
	}
  }
  bool IsDependencySet(size_t index) override {
	if (index >= 2) {
	  throw std::runtime_error(GetDependencyIndexError("check"));
	}
	switch (index) {
	  case 0:return IsRandomGeneratorSet();
	  case 1:
	  default:return IsPrimalityTestSet();
	}
  }
  ACryptoElement &GetDependency(size_t index) override {
	if (index >= 1) {
	  throw std::runtime_error(GetDependencyIndexError("get"));
	}
	switch (index) {
	  case 0:return GetRandomGenerator();
	  case 1:
	  default:return GetPrimalityTest();
	}
  }
  BigNumber GenerateRandomPrimeBigNumber(size_t bits) override;
  std::string GetHeader() override;
  void SetRandomGenerator(std::unique_ptr<ACryptoElement> random_generator);
  bool IsRandomGeneratorSet() const;
  ACryptoElement &GetRandomGenerator() const;
  void SetPrimalityTest(std::unique_ptr<ACryptoElement> primality_test);
  bool IsPrimalityTestSet() const;
  ACryptoElement &GetPrimalityTest() const;
  const std::string &GetElementName() const override { return GetName(); };
  const std::string &GetElementTypeName() const override { return GetTypeName(); };
  static const uint16_t id = 1;
  static const std::string &GetName() {
	static std::string name = "custom-prime-generator";
	return name;
  };
 private:
  std::unique_ptr<ARandomGenerator> random_generator_;
  std::unique_ptr<APrimalityTest> primality_test_;
};

}
#endif //HCL_SRC_SERVICES_CRYPTO_PRIMEGENERATORS_CUSTOMPRIMEGENERATOR_H_
