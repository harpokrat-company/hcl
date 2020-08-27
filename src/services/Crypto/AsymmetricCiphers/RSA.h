//
// Created by antoine on 20/07/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_ASYMMETRICCIPHERS_RSA_H_
#define HCL_SRC_SERVICES_CRYPTO_ASYMMETRICCIPHERS_RSA_H_

#include <gmpxx.h>
#include <gmp.h>

#include "../AutoRegisterer.h"
#include "AAsymmetricCipher.h"

namespace HCL::Crypto {

class RSA : public AutoRegisterer<AAsymmetricCipher, RSA> {
 public:
  RSA();
  RSA(const std::string &header, size_t &header_length);
  //TODO: Add PrimeGenerator Dependency
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
  mpz_class Encrypt(const mpz_class &key, const mpz_class &content);
  mpz_class Decrypt(const mpz_class &key, const mpz_class &content);
  std::string GetHeader() override;
  const std::string &GetElementName() const override { return GetName(); };
  const std::string &GetElementTypeName() const override { return GetTypeName(); };
  static const uint16_t id = 1;
  static const std::string &GetName() {
	static std::string name = "rsa";
	return name;
  };
 private:
};
}

#endif //HCL_SRC_SERVICES_CRYPTO_ASYMMETRICCIPHERS_RSA_H_
