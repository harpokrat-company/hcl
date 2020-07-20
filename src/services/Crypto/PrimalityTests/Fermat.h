//
// Created by antoine on 10/06/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_PRIMALITYTESTS_FERMAT_H_
#define HCL_SRC_SERVICES_CRYPTO_PRIMALITYTESTS_FERMAT_H_

#include "../AutoRegisterer.h"
#include "APrimalityTest.h"
#include "../RandomGenerators/ARandomGenerator.h"

namespace HCL::Crypto {

class Fermat : public AutoRegisterer<APrimalityTest, Fermat> {
 public:
  Fermat();
  Fermat(const std::string &header, size_t &header_length);
  const std::vector<std::string> &GetDependenciesTypes() override {
	static const std::vector<std::string> dependencies(
		{
			ARandomGenerator::GetName(),
		});
	return dependencies;
  }
  void SetDependency(std::unique_ptr<ACryptoElement> dependency, size_t index) override {
	if (index >= 1) {
	  throw std::runtime_error(GetDependencyIndexError("set"));
	}
	switch (index) {
	  case 0:
	  default:SetRandomGenerator(std::move(dependency));
	}
  }
  bool IsDependencySet(size_t index) override {
	if (index >= 1) {
	  throw std::runtime_error(GetDependencyIndexError("check"));
	}
	switch (index) {
	  case 0:
	  default:return IsRandomGeneratorSet();
	}
  }
  ACryptoElement &GetDependency(size_t index) override {
	if (index >= 1) {
	  throw std::runtime_error(GetDependencyIndexError("get"));
	}
	switch (index) {
	  case 0:
	  default:return GetRandomGenerator();
	}
  }
  bool IsPrime(BigNumber number) override;
  std::string GetHeader() override;
  void SetRandomGenerator(std::unique_ptr<ACryptoElement> random_generator);
  bool IsRandomGeneratorSet() const;
  ACryptoElement &GetRandomGenerator() const;
  const std::string &GetElementName() const override { return GetName(); };
  const std::string &GetElementTypeName() const override { return GetTypeName(); };
  static const uint16_t id = 1;
  static const std::string &GetName() {
	static std::string name = "fermat";
	return name;
  };
 private:
  std::unique_ptr<ARandomGenerator> random_generator_;
};

}
#endif //HCL_SRC_SERVICES_CRYPTO_PRIMALITYTESTS_FERMAT_H_
