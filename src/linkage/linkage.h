//
// Created by neodar on 13/01/2020.
//

#ifndef HCL_LINKAGE_H
#define HCL_LINKAGE_H

#ifdef __EMSCRIPTEN__
#include <emscripten/emscripten.h>
#define EXPORT_FUNCTION EMSCRIPTEN_KEEPALIVE
#else
#define EXPORT_FUNCTION
#endif

#endif //HCL_LINKAGE_H
