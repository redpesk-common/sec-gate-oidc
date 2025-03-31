cmake_policy(SET CMP0048 NEW)
project(sec-gate-oidc VERSION 1.1.0)
CMAKE_MINIMUM_REQUIRED(VERSION 3.6)
include(${CMAKE_CURRENT_SOURCE_DIR}/conf.d/cmake/config.cmake)

include(GNUInstallDirs)
configure_file(${PROJECT_NAME}.pc.in ${PROJECT_NAME}.pc @ONLY)

INSTALL(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}.pc
    DESTINATION
    ${CMAKE_INSTALL_LIBDIR}/pkgconfig
)
