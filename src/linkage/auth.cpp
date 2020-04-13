//
// Created by neodar on 12/01/2020.
//

#include <sstream>
#include <iomanip>
#include "auth.h"
#include "../services/Crypto/Base64.h"
#include "../services/Crypto/Factory.h"
#include "../services/Crypto/HashFunctions/AHashFunction.h"

extern "C" {
std::string *EXPORT_FUNCTION GetBasicAuthString(const char *raw_email, const char *raw_password) {
  auto sha512 = HCL::Crypto::Factory<HCL::Crypto::AHashFunction>::BuildTypedFromName("sha512");
  std::string email(raw_email);
  std::string password(sha512->HashData(raw_password));
  std::stringstream hex_hash;

  // TODO Clean format with signature ?
  return new std::string("Basic " + HCL::Crypto::Base64::Encode(email + ":" + HCL::Crypto::Base64::Encode(password)));
}
}
