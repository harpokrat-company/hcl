//
// Created by neodar on 12/01/2020.
//

#ifndef HCL_AUTH_LINKAGE_H
#define HCL_AUTH_LINKAGE_H

#include <string>

extern "C" std::string *GetBasicAuth(const char *raw_email, const char *raw_password);

#endif //HCL_AUTH_LINKAGE_H
