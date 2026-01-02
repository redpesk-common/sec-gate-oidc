pkg_check_modules(DEPS REQUIRED IMPORTED_TARGET
	libafb>=5.3.8
	libcurl>=7.55.0
	librp-utils-core
)

# Define project Targets
add_library(curl-glue-afb STATIC curl-client.c http-gluafb.c)

# compilation include path
target_include_directories(curl-glue-afb BEFORE PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(curl-glue-afb PkgConfig::DEPS)
