cmake_minimum_required(VERSION 3.10)
project(hcl)

if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif ()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS_RELEASE "-Ofast")

set(LIBRARY_SOURCE_FILES
    src/linkage/auth.cpp
    src/linkage/auth.h
    src/services/Crypto/Base64.cpp
    src/services/Crypto/Base64.h
    src/linkage/string_utils.cpp
    src/linkage/string_utils.h
    src/services/Harpokrat/Secret.cpp
    src/services/Harpokrat/Secret.h
    src/services/Harpokrat/User.cpp
    src/services/Harpokrat/User.h
    src/linkage/secret.cpp
    src/linkage/secret.h
    src/linkage/user.cpp
    src/linkage/user.h
    src/linkage/linkage.h
    src/services/Crypto/AES.cpp
    src/services/Crypto/AES.h
    src/services/Crypto/RijndaelKeySchedule.cpp
    src/services/Crypto/RijndaelKeySchedule.tpp
    src/services/Crypto/RijndaelKeySchedule.h
    src/services/Crypto/RijndaelSubstitutionBox.cpp
    src/services/Crypto/RijndaelSubstitutionBox.h
    src/services/Crypto/CryptoHelper.cpp
    src/services/Crypto/CryptoHelper.h)

set(TEST_SOURCE_FILES
    tests/main.cpp
    tests/AES.cpp
    tests/RijndaelKeySchedule.cpp)

add_library(hcl SHARED ${LIBRARY_SOURCE_FILES})

add_executable(hcl_test_suite ${LIBRARY_SOURCE_FILES} ${TEST_SOURCE_FILES})
