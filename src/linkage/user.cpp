//
// Created by neodar on 13/01/2020.
//

#include "user.h"

extern "C" {
HCL::User *EXPORT_FUNCTION CreateUser(
        const char *email,
        const char *password,
        const char *first_name,
        const char *last_name
) {
    return new HCL::User(email, password, first_name, last_name);
}

const char *EXPORT_FUNCTION GetEmailFromUser(HCL::User *user) {
    return user->GetEmail().c_str();
}

void EXPORT_FUNCTION UpdateUserEmail(HCL::User *user, const char *email) {
    user->SetEmail(email);
}

const char *EXPORT_FUNCTION GetPasswordFromUser(HCL::User *user) {
    return user->GetPassword().c_str();
}

void EXPORT_FUNCTION UpdateUserPassword(HCL::User *user, const char *password) {
    user->SetPassword(password);
}

const char *EXPORT_FUNCTION GetFirstNameFromUser(HCL::User *user) {
    return user->GetFirstName().c_str();
}

void EXPORT_FUNCTION UpdateUserFirstName(HCL::User *user, const char *first_name) {
    user->SetFirstName(first_name);
}

const char *EXPORT_FUNCTION GetLastNameFromUser(HCL::User *user) {
    return user->GetLastName().c_str();
}

void EXPORT_FUNCTION UpdateUserLastName(HCL::User *user, const char *last_name) {
    user->SetLastName(last_name);
}

void EXPORT_FUNCTION DeleteUser(HCL::User *user) {
    delete user;
}
}
