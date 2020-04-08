//
// Created by neodar on 30/03/2020.
//

#include "tests.h"
#include "../src/services/Crypto/AutoRegisterer.h"
#include "../src/services/Crypto/HashFunctions/AHashFunction.h"
#include "../src/services/Crypto/HashFunctions/SHA256.h"

static int (*test_functions[])() = {
//    RijndaelKeyScheduleTests,
    AESTests,
    SHATests,
    FullWorkflowTests,
    nullptr
};

int main() {
  for (int i = 0; test_functions[i] != nullptr; ++i) {
    if (test_functions[i]() != 0) {
      return 1;
    }
  }
  return 0;
}
