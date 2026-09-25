if(NOT CMAKE_INSTALL_SYSTEMDUSERUNITDIR)
    set(CMAKE_INSTALL_SYSTEMDUSERUNITDIR "lib/systemd/user"
        CACHE PATH "Systemd user unit directory")
endif()

configure_file(
    pkinit-trust-brokerd.service.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/pkinit-trust-brokerd.service @ONLY
)

install(
    FILES
        ${CMAKE_CURRENT_BINARY_DIR}/pkinit-trust-brokerd.service
        pkinit-trust-brokerd.socket
    DESTINATION
        ${CMAKE_INSTALL_SYSTEMDUSERUNITDIR}
)
