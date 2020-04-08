//
// Created by neodar on 07/04/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_MESSAGEAUTHENTICATIONCODES_AMESSAGEAUTHENTICATIONCODE_H_
#define HCL_SRC_SERVICES_CRYPTO_MESSAGEAUTHENTICATIONCODES_AMESSAGEAUTHENTICATIONCODE_H_

#include <string>
#include "../ACryptoElement.h"

namespace HCL::Crypto {

class AMessageAuthenticationCode : public ACryptoElement {
 public:
  virtual ~AMessageAuthenticationCode() = default;
  virtual std::string SignMessage(const std::string &key, const std::string &message) = 0;
  virtual std::string GetHeader() = 0;
  static const std::string &GetName() {
    static std::string name = "message-authentication-code";
    return name;
  };
};
}

#endif //HCL_SRC_SERVICES_CRYPTO_MESSAGEAUTHENTICATIONCODES_AMESSAGEAUTHENTICATIONCODE_H_
