
# extra dependencies
pkg_check_modules (PCSC REQUIRED IMPORTED_TARGET libpcsclite)

# library
add_library(pcscd-glue STATIC pcsc-config.c pcsc-glue.c)
target_link_libraries(pcscd-glue PUBLIC PkgConfig::PCSC pthread)
target_include_directories(pcscd-glue INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})

# client
add_executable(pcscd-client client-pcsc.c)
add_dependencies(pcscd-client pcscd-glue)
target_link_libraries(pcscd-client PUBLIC PkgConfig::PCSC libafb.so json-c pthread pcscd-glue)
install(TARGETS pcscd-client DESTINATION ${APPDIR}/bin)

