pkg_check_modules(PCSC REQUIRED IMPORTED_TARGET
	json-c
	librp-utils-core
	librp-utils-json-c
	libpcsclite
)

# library
add_library(pcscd-glue STATIC pcsc-config.c pcsc-glue.c)
target_link_libraries(pcscd-glue PUBLIC PkgConfig::PCSC pthread)
target_include_directories(pcscd-glue INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})

# client
add_executable(pcscd-client client-pcsc.c)
add_dependencies(pcscd-client pcscd-glue)
target_link_libraries(pcscd-client PRIVATE pcscd-glue)
install(TARGETS pcscd-client DESTINATION ${APPDIR}/bin)

