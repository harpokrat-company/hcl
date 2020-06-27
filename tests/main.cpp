//
// Created by neodar on 30/03/2020.
//

#include "tests.h"

static int (*test_functions[])() = {
    RijndaelKeyScheduleTests,
    AESTests,
    SHATests,
    FullWorkflowTests,
    BigNumberTests,
    PrimalityTests,
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
