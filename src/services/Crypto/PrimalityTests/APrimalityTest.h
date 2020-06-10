//
// Created by antoine on 10/06/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_PRIMALITYTESTS_APRIMALITYTEST_H_
#define HCL_SRC_SERVICES_CRYPTO_PRIMALITYTESTS_APRIMALITYTEST_H_

#include "../ACryptoElement.h"

namespace HCL::Crypto {

class APrimalityTest : public ACryptoElement {
 public:
  virtual ~APrimalityTest() = default;
  virtual std::string GetHeader() = 0;
  //TODO Temporary function signature (not sure)
  virtual bool IsPrime(size_t number) = 0;
  static const std::string &GetName() {
	static std::string name = "primality-test";
	return name;
  };
};
}

#endif //HCL_SRC_SERVICES_CRYPTO_PRIMALITYTESTS_APRIMALITYTEST_H_
