

# Define project Targets
add_library(builtin-idps STATIC idp-github.c idp-ldap.c idp-oidc.c)

add_dependencies(builtin-idps curl-glue-afb sgoidc)
target_link_libraries(builtin-idps curl-glue-afb sgoidc)
target_include_directories(builtin-idps BEFORE PRIVATE ..)
