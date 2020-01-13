//
// Created by neodar on 12/01/2020.
//

#ifndef HCL_STRING_UTILS_LINKAGE_H
#define HCL_STRING_UTILS_LINKAGE_H

#include <string>

extern "C" {
    void DeleteString(std::string *);
    const char *GetCharArrayFromString(std::string *);
};

#endif //HCL_STRING_UTILS_LINKAGE_H
