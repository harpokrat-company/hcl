//
// Created by neodar on 12/01/2020.
//

#include "auth.h"
#include "../services/Crypto/Base64.h"

extern "C" {
std::string *EXPORT_FUNCTION GetBasicAuthString(const char *raw_email, const char *raw_password) {
    std::string email(raw_email);
    std::string password(raw_password); // TODO password derivation

    return new std::string("Basic " + HCL::Crypto::Base64::Encode(email + ":" + password));
}
}
