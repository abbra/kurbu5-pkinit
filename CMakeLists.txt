cmake_minimum_required(VERSION 3.20)
project(kurbu5-pkinit VERSION 0.1.0 LANGUAGES C)

list(APPEND CMAKE_MODULE_PATH "${kurbu5-pkinit_SOURCE_DIR}/cmake/Modules")

include(GNUInstallDirs)

set(KRB5_PLUGIN_PREAUTH_DIR "${CMAKE_INSTALL_LIBDIR}/krb5/plugins/preauth"
    CACHE PATH "MIT Kerberos preauth plugin directory")

include(Corrosion)

corrosion_import_crate(
    MANIFEST_PATH ${kurbu5-pkinit_SOURCE_DIR}/Cargo.toml
    CRATES kurbu5-pkinit pkinit-trust-brokerd pkinit-trust-ctl
)

set(_PLUGIN_PERMS
    OWNER_READ OWNER_WRITE OWNER_EXECUTE
    GROUP_READ GROUP_EXECUTE
    WORLD_READ WORLD_EXECUTE)

install(FILES $<TARGET_FILE:kurbu5_pkinit-shared>
        DESTINATION ${KRB5_PLUGIN_PREAUTH_DIR}
        RENAME pkinit.so
        PERMISSIONS ${_PLUGIN_PERMS})

install(PROGRAMS $<TARGET_FILE:pkinit-trust-brokerd>
        DESTINATION ${CMAKE_INSTALL_BINDIR})

install(PROGRAMS $<TARGET_FILE:pkinit-trust-ctl>
        DESTINATION ${CMAKE_INSTALL_BINDIR})

add_subdirectory(contrib/systemd)
