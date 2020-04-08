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
    src/services/Crypto/BlockCiphers/Rijndael.h
    src/services/Crypto/RijndaelKeySchedule.cpp
    src/services/Crypto/RijndaelKeySchedule.tpp
    src/services/Crypto/RijndaelKeySchedule.h
    src/services/Crypto/RijndaelSubstitutionBox.cpp
    src/services/Crypto/RijndaelSubstitutionBox.h
    src/services/Crypto/CryptoHelper.cpp
    src/services/Crypto/CryptoHelper.h
    src/services/Crypto/Ciphers/ACipher.cpp
    src/services/Crypto/Ciphers/ACipher.h
    src/services/Crypto/EncryptedBlob.cpp
    src/services/Crypto/EncryptedBlob.h
    src/services/Crypto/SuperFactory.cpp
    src/services/Crypto/SuperFactory.h
    src/services/Crypto/Factory.h
    src/services/Crypto/Ciphers/BlockCipherScheme.cpp
    src/services/Crypto/Ciphers/BlockCipherScheme.h
    src/services/Crypto/BlockCiphers/ABlockCipher.cpp
    src/services/Crypto/BlockCiphers/ABlockCipher.h
    src/services/Crypto/BlockCiphers/AES128.cpp
    src/services/Crypto/BlockCiphers/AES128.h
    src/services/Crypto/BlockCiphers/AES192.cpp
    src/services/Crypto/BlockCiphers/AES192.h
    src/services/Crypto/BlockCiphers/AES256.cpp
    src/services/Crypto/BlockCiphers/AES256.h
    src/services/Crypto/BlockCipherModes/ABlockCipherMode.cpp
    src/services/Crypto/BlockCipherModes/ABlockCipherMode.h
    src/services/Crypto/BlockCipherModes/CBC.cpp
    src/services/Crypto/BlockCipherModes/CBC.h
    src/services/Crypto/Padding/APaddedCipher.cpp
    src/services/Crypto/Padding/APaddedCipher.h
    src/services/Crypto/Padding/APadding.cpp
    src/services/Crypto/Padding/APadding.h
    src/services/Crypto/KeyStretchingFunctions/AKeyStretchingFunction.cpp
    src/services/Crypto/KeyStretchingFunctions/AKeyStretchingFunction.h
    src/services/Crypto/HashFunctions/AHashFunction.cpp
    src/services/Crypto/HashFunctions/AHashFunction.h
    src/services/Crypto/RandomGenerators/ARandomGenerator.cpp
    src/services/Crypto/RandomGenerators/ARandomGenerator.h
    src/services/Crypto/BlockCipherModes/AInitializationVectorBlockCipherMode.cpp
    src/services/Crypto/BlockCipherModes/AInitializationVectorBlockCipherMode.h
    src/services/Crypto/Padding/PKCS7.cpp
    src/services/Crypto/Padding/PKCS7.h
    src/services/Crypto/RandomGenerators/MT19937.cpp
    src/services/Crypto/RandomGenerators/MT19937.h
    src/services/Crypto/KeyStretchingFunctions/PBKDF2.cpp
    src/services/Crypto/KeyStretchingFunctions/PBKDF2.h
    src/services/Crypto/MessageAuthenticationCodes/AMessageAuthenticationCode.cpp
    src/services/Crypto/MessageAuthenticationCodes/AMessageAuthenticationCode.h
    src/services/Crypto/MessageAuthenticationCodes/HMAC.cpp
    src/services/Crypto/MessageAuthenticationCodes/HMAC.h
    src/services/Crypto/HashFunctions/SHA256.cpp
    src/services/Crypto/HashFunctions/SHA256.h
    src/services/Crypto/AutoRegisterer.h
    src/services/Crypto/AFactory.h
    src/services/Crypto/ACryptoElement.h)

#set(TEST_SOURCE_FILES
#    tests/main.cpp
#    tests/AES.cpp
#    tests/SHA.cpp
#    tests/FullWorkflow.cpp
#    tests/RijndaelKeySchedule.cpp)

add_library(hcl SHARED ${LIBRARY_SOURCE_FILES})

#add_executable(hcl_test_suite ${LIBRARY_SOURCE_FILES} ${TEST_SOURCE_FILES})
