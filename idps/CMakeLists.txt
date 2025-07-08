

# Define project Targets
add_library(idps-builtin STATIC idp-builtin.c idp-github.c idp-ldap.c idp-oidc.c)

add_dependencies(idps-builtin curl-glue-afb)
target_link_libraries(idps-builtin curl-glue-afb)

target_include_directories(idps-builtin
	    INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}
	    PRIVATE ${CMAKE_SOURCE_DIR}/src)
