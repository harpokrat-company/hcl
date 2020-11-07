//
// Created by neodar on 12/01/2020.
//

#include "string_utils.h"

extern "C" {
std::string *EXPORT_FUNCTION GetExceptionMessage(std::exception *exception) {
  return new std::string(exception->what());
}

void EXPORT_FUNCTION DeleteString(std::string *string) {
    delete string;
}

const char *EXPORT_FUNCTION GetCharArrayFromString(std::string *string) {
    return string->c_str();
}
}
