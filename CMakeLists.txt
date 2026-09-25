cmake_minimum_required(VERSION 3.20)
project(kurbu5-pkinit VERSION 0.1.0 LANGUAGES C)

list(APPEND CMAKE_MODULE_PATH "${kurbu5-pkinit_SOURCE_DIR}/cmake/Modules")

include(GNUInstallDirs)

set(KRB5_PLUGIN_PREAUTH_DIR "${CMAKE_INSTALL_LIBDIR}/krb5/plugins/preauth"
    CACHE PATH "MIT Kerberos preauth plugin directory")
