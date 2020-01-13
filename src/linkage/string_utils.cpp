//
// Created by neodar on 12/01/2020.
//

#include "string_utils.h"

extern "C" {
    void DeleteString(std::string *string) {
        delete string;
    }

    const char *GetCharArrayFromString(std::string *string) {
        return string->c_str();
    }
}
