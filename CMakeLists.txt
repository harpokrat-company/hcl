cmake_minimum_required(VERSION 3.13)
project(hcl)

set(CMAKE_CXX_STANDARD 17)

add_library(hcl SHARED library.cpp library.h services/Crypto/Base64.cpp services/Crypto/Base64.h)
