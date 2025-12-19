
# Define project Targets
find_library(PAM_DEVEL pam REQUIRED)
add_library(idp-sgate-pam-auth MODULE oidc-pam.c)

add_dependencies(idp-sgate-pam-auth curl-glue-afb sec-gate-oidc sgoidc)
target_include_directories(idp-sgate-pam-auth BEFORE PRIVATE .)
target_link_libraries(idp-sgate-pam-auth curl-glue-afb pam sec-gate-oidc sgoidc)

install(TARGETS idp-sgate-pam-auth
	DESTINATION ${APPDIR}/lib/plugins)

