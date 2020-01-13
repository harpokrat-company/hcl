//
// Created by neodar on 12/01/2020.
//

#include "string_utils.h"

extern "C" {
void EXPORT_FUNCTION DeleteString(std::string *string) {
    delete string;
}

const char *EXPORT_FUNCTION GetCharArrayFromString(std::string *string) {
    return string->c_str();
}
}
