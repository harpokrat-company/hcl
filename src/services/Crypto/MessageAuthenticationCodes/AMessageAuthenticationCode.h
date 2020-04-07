//
// Created by neodar on 07/04/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_MESSAGEAUTHENTICATIONCODES_AMESSAGEAUTHENTICATIONCODE_H_
#define HCL_SRC_SERVICES_CRYPTO_MESSAGEAUTHENTICATIONCODES_AMESSAGEAUTHENTICATIONCODE_H_

#include <string>

namespace HCL::Crypto {

class AMessageAuthenticationCode {
 public:
  virtual std::string SignMessage(const std::string &key, const std::string &message) = 0;
  virtual std::string GetHeader() = 0;
};
}

#endif //HCL_SRC_SERVICES_CRYPTO_MESSAGEAUTHENTICATIONCODES_AMESSAGEAUTHENTICATIONCODE_H_
