cmake_minimum_required(VERSION 3.10)
project(hcl)

set(CMAKE_CXX_STANDARD 17)

add_library(hcl SHARED src/linkage/auth.cpp src/linkage/auth.h src/services/Crypto/Base64.cpp src/services/Crypto/Base64.h src/linkage/string_utils.cpp src/linkage/string_utils.h src/services/Harpokrat/Secret.cpp src/services/Harpokrat/Secret.h src/services/Harpokrat/User.cpp src/services/Harpokrat/User.h src/linkage/secret.cpp src/linkage/secret.h src/linkage/user.cpp src/linkage/user.h src/linkage/linkage.h)
