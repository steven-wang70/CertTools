set OPENSSL_DIR=D:\steven\apps\openssl-1.0.2e-win32-x86_64
set INCLUDE_DIR=%OPENSSL_DIR%\include
set LIB_DIR=%OPENSSL_DIR%\lib

CL /I%INCLUDE_DIR% readCerts.cpp /link /LIBPATH:%LIB_DIR% /DEFAULTLIB:"libcrypto.dll.a