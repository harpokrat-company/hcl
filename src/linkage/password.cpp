//
// Created by neodar on 13/01/2020.
//

#include "password.h"

extern "C" {
HCL::Password *EXPORT_FUNCTION CreatePassword() {
    return new HCL::Password();
}

bool EXPORT_FUNCTION CorrectPasswordDecryption(HCL::Password *password) {
  return password->CorrectDecryption();
}

const char *EXPORT_FUNCTION GetNameFromPassword(HCL::Password *password) {
  return password->GetName().c_str();
}

const char *EXPORT_FUNCTION GetLoginFromPassword(HCL::Password *password) {
    return password->GetLogin().c_str();
}

const char *EXPORT_FUNCTION GetPasswordFromPassword(HCL::Password *password) {
    return password->GetPassword().c_str();
}

const char *EXPORT_FUNCTION GetDomainFromPassword(HCL::Password *password) {
    return password->GetDomain().c_str();
}

void EXPORT_FUNCTION UpdatePasswordName(HCL::Password *password, const char *name) {
    password->SetName(name);
}

void EXPORT_FUNCTION UpdatePasswordLogin(HCL::Password *password, const char *login) {
    password->SetLogin(login);
}

void EXPORT_FUNCTION UpdatePasswordPassword(HCL::Password *password, const char *password_value) {
    password->SetPassword(password_value);
}

void EXPORT_FUNCTION UpdatePasswordDomain(HCL::Password *password, const char *domain) {
    password->SetDomain(domain);
}

std::string *EXPORT_FUNCTION GetContentStringFromPassword(HCL::Password *password, const char *key) {
    return new std::string(password->Serialize(key));
}

void EXPORT_FUNCTION DeletePassword(HCL::Password *password) {
    delete password;
}
}
