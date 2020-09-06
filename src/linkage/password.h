//
// Created by neodar on 13/01/2020.
//

#ifndef HCL_PASSWORD_LINKAGE_H
#define HCL_PASSWORD_LINKAGE_H

#include <string>
#include "linkage.h"
#include "../services/Harpokrat/Secrets/Password.h"

extern "C" {
HCL::Password *CreatePassword();
bool CorrectPasswordDecryption(HCL::Password *password);
const char *GetNameFromPassword(HCL::Password *password);
const char *GetLoginFromPassword(HCL::Password *password);
const char *GetPasswordFromPassword(HCL::Password *password);
const char *GetDomainFromPassword(HCL::Password *password);
void UpdatePasswordName(HCL::Password *password, const char *name);
void UpdatePasswordLogin(HCL::Password *password, const char *login);
void UpdatePasswordPassword(HCL::Password *password, const char *password_value);
void UpdatePasswordDomain(HCL::Password *password, const char *domain);
std::string *GetContentStringFromPassword(HCL::Password *password, const char *key);
void DeletePassword(HCL::Password *password);
};

#endif //HCL_PASSWORD_LINKAGE_H
