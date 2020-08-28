//
// Created by antoine on 20/07/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_ASYMMETRICCIPHERS_RSA_H_
#define HCL_SRC_SERVICES_CRYPTO_ASYMMETRICCIPHERS_RSA_H_

#include <gmpxx.h>
#include <gmp.h>

#include "../AutoRegisterer.h"
#include "AAsymmetricCipher.h"
#include "../PrimeGenerators/APrimeGenerator.h"
#include "KeyPair.h"

namespace HCL::Crypto {

class RSA : public AutoRegisterer<AAsymmetricCipher, RSA> {
 public:
  RSA();
  RSA(const std::string &header, size_t &header_length);
  const std::vector<std::string> &GetDependenciesTypes() override {
	static const std::vector<std::string> dependencies(
		{
			APrimeGenerator::GetName(),
		});
	return dependencies;
  }
  void SetDependency(std::unique_ptr<ACryptoElement> dependency, size_t index) override {
	if (index >= 1) {
	  throw std::runtime_error(GetDependencyIndexError("set"));
	}
	switch (index) {
	  case 0:
	  default:SetPrimeGenerator(std::move(dependency));
	}
  }
  bool IsDependencySet(size_t index) override {
	if (index >= 1) {
	  throw std::runtime_error(GetDependencyIndexError("check"));
	}
	switch (index) {
	  case 0:
	  default:return IsPrimeGeneratorSet();
	}
  }
  ACryptoElement &GetDependency(size_t index) override {
	if (index >= 1) {
	  throw std::runtime_error(GetDependencyIndexError("get"));
	}
	switch (index) {
	  case 0:
	  default:return GetPrimeGenerator();
	}
  }
  void SetPrimeGenerator(std::unique_ptr<ACryptoElement> prime_generator);
  bool IsPrimeGeneratorSet() const;
  ACryptoElement &GetPrimeGenerator() const;
  KeyPair GenerateKeyPair(size_t bits);
  mpz_class Encrypt(const std::pair<mpz_class, mpz_class> &key, const mpz_class &content);
  mpz_class Decrypt(const std::pair<mpz_class, mpz_class> &key, const mpz_class &content);
  std::string GetHeader() override;
  const std::string &GetElementName() const override { return GetName(); };
  const std::string &GetElementTypeName() const override { return GetTypeName(); };
  static const uint16_t id = 1;
  static const std::string &GetName() {
	static std::string name = "rsa";
	return name;
  };
 private:
  std::unique_ptr<APrimeGenerator> prime_generator_;
  gmp_randclass r1;
  bool key_seeded;
};
}

#endif //HCL_SRC_SERVICES_CRYPTO_ASYMMETRICCIPHERS_RSA_H_
