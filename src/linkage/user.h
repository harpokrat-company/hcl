//
// Created by neodar on 13/01/2020.
//

#ifndef HCL_USER_LINKAGE_H
#define HCL_USER_LINKAGE_H

#include "linkage.h"
#include "../services/Harpokrat/User.h"

extern "C" {
HCL::User *EXPORT_FUNCTION CreateUser(const char *, const char *, const char *, const char *);
const char *EXPORT_FUNCTION GetEmailFromUser(HCL::User *);
void EXPORT_FUNCTION UpdateUserEmail(HCL::User *, const char *);
const char *EXPORT_FUNCTION GetPasswordFromUser(HCL::User *);
void EXPORT_FUNCTION UpdateUserPassword(HCL::User *, const char *);
const char *EXPORT_FUNCTION GetFirstNameFromUser(HCL::User *);
void EXPORT_FUNCTION UpdateUserFirstName(HCL::User *, const char *);
const char *EXPORT_FUNCTION GetLastNameFromUser(HCL::User *);
void EXPORT_FUNCTION UpdateUserLastName(HCL::User *, const char *);
void EXPORT_FUNCTION DeleteUser(HCL::User *);
};

#endif //HCL_USER_LINKAGE_H
